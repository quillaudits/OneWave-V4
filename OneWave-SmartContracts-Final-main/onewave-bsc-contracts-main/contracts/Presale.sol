// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

interface IPresaleVesting {
    function createVestingSchedule(address beneficiary, uint256 amount, uint256 roundId) external;
}

/// @title Presale — Token sale manager for the OneWave ecosystem
/// @author OneWave
/// @notice Manages multi-round presale: round configuration, token purchases with stablecoins or BNB,
///         and automatic vesting schedule creation via PresaleVesting
/// @dev Does NOT hold or release WAVE tokens directly — assigns purchases to PresaleVesting.
///      Payments (stablecoins/BNB) are held in this contract until admin withdrawal.
///      Per-token pricing supports payment tokens with different decimals (6-dec stables, 18-dec BNB).
///      Per-round whitelist supports private sale access control.
contract Presale is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /// @dev Thrown when a zero address is provided where a valid address is required
    error Presale__ZeroAddress();

    /// @dev Thrown when a zero amount is provided where a positive value is required
    error Presale__ZeroAmount();

    /// @dev Thrown when a round ID is outside the valid range (1–3)
    error Presale__InvalidRound(uint256 roundId);

    /// @dev Thrown when the presale is not currently active
    error Presale__NotActive();

    /// @dev Thrown when the presale is already in the requested state
    error Presale__AlreadyInState(bool active);

    /// @dev Thrown when a round has not been configured yet
    error Presale__RoundNotConfigured(uint256 roundId);

    /// @dev Thrown when purchasing would exceed the round's allocation cap
    error Presale__RoundCapExceeded(uint256 roundId, uint256 requested, uint256 available);

    /// @dev Thrown when a purchase amount is below the minimum wallet limit
    error Presale__BelowMinBuy(uint256 amount, uint256 minBuy);

    /// @dev Thrown when a purchase would push a wallet above the maximum buy limit
    error Presale__ExceedsMaxBuy(uint256 total, uint256 maxBuy);

    /// @dev Thrown when a payment token is not whitelisted
    error Presale__PaymentTokenNotAccepted(address token);

    /// @dev Thrown when BNB transfer to this contract fails or msg.value is zero
    error Presale__InvalidNativePayment();

    /// @dev Thrown when BNB withdrawal to recipient fails
    error Presale__NativeTransferFailed();

    /// @dev Thrown when setting allocation below already-sold amount
    error Presale__AllocationBelowSold(uint256 allocation, uint256 sold);

    /// @dev Thrown when attempting to withdraw more than the contract balance
    error Presale__InsufficientBalance(uint256 requested, uint256 available);

    /// @dev Thrown when no per-token price is set for the round + payment token pair
    error Presale__TokenPriceNotSet(uint256 roundId, address paymentToken);

    /// @dev Thrown when a non-whitelisted buyer tries to purchase in a whitelist-required round
    error Presale__NotWhitelisted(address buyer);

    /// @notice Emitted when a round is configured or updated
    /// @param roundId Presale round (1–3)
    /// @param allocation Total WAVE tokens available in this round
    event RoundConfigured(uint256 indexed roundId, uint256 allocation);

    /// @notice Emitted when the presale is started
    event PresaleStarted();

    /// @notice Emitted when the presale is stopped
    event PresaleStopped();

    /// @notice Emitted when a user purchases tokens
    /// @param buyer Address of the purchaser
    /// @param roundId Presale round
    /// @param paymentToken Address of the payment token (address(0) for BNB)
    /// @param paymentAmount Payment amount in payment token units
    /// @param waveAmount WAVE tokens assigned to the buyer
    event TokensPurchased(
        address indexed buyer,
        uint256 indexed roundId,
        address paymentToken,
        uint256 paymentAmount,
        uint256 waveAmount
    );

    /// @notice Emitted when a payment token is whitelisted or removed
    /// @param token Address of the payment token
    /// @param accepted Whether the token is now accepted
    event PaymentTokenUpdated(address indexed token, bool accepted);

    /// @notice Emitted when wallet purchase limits are updated
    /// @param minBuy Minimum WAVE tokens per purchase
    /// @param maxBuy Maximum WAVE tokens per wallet per round
    event WalletLimitsUpdated(uint256 minBuy, uint256 maxBuy);

    /// @notice Emitted when admin withdraws collected funds
    /// @param token Address of the withdrawn token (address(0) for BNB)
    /// @param recipient Withdrawal recipient
    /// @param amount Amount withdrawn
    event FundsWithdrawn(address indexed token, address indexed recipient, uint256 amount);

    /// @notice Emitted when a per-token price is set for a round
    /// @param roundId Presale round (1–3)
    /// @param paymentToken Address of the payment token (address(0) for BNB)
    /// @param price Price per WAVE in payment token's native units
    event TokenPriceUpdated(uint256 indexed roundId, address indexed paymentToken, uint256 price);

    /// @notice Emitted when a buyer is added to or removed from the whitelist
    /// @param buyer Address of the buyer
    /// @param allowed Whether the buyer is now whitelisted
    event WhitelistUpdated(address indexed buyer, bool allowed);

    /// @notice Emitted when a round's whitelist requirement is toggled
    /// @param roundId Presale round (1–3)
    /// @param required Whether whitelist is now required for this round
    event RoundWhitelistToggled(uint256 indexed roundId, bool required);

    uint256 public constant ROUND_COUNT = 3;

    struct Round {
        uint256 allocation;    // total WAVE tokens for this round (in wei)
        uint256 sold;          // WAVE tokens sold so far (in wei)
        bool configured;
    }

    IPresaleVesting public immutable presaleVesting;
    bool public active;

    uint256 public minBuyAmount; // minimum WAVE per purchase (in wei)
    uint256 public maxBuyAmount; // maximum WAVE per wallet per round (in wei)

    mapping(uint256 => Round) public rounds;
    mapping(address => bool) public acceptedPaymentTokens;
    mapping(address => mapping(uint256 => uint256)) public buyerPurchases; // buyer => roundId => WAVE amount

    /// @dev Per-token price per round: price = payment token's native smallest unit per 1 WAVE.
    ///      USDT (6 dec) at $0.25/WAVE → tokenPrices[1][usdt] = 250_000
    ///      BNB (18 dec) at $600/BNB, $0.25/WAVE → tokenPrices[1][address(0)] = 416_666_666_666_666
    mapping(uint256 => mapping(address => uint256)) public tokenPrices;

    mapping(address => bool) public whitelisted; // global buyer whitelist
    mapping(uint256 => bool) public whitelistRequired; // per-round whitelist enforcement

    /// @notice Deploys Presale with the PresaleVesting contract address
    /// @param _presaleVesting Address of the PresaleVesting contract
    constructor(address _presaleVesting) {
        if (_presaleVesting == address(0)) revert Presale__ZeroAddress();
        presaleVesting = IPresaleVesting(_presaleVesting);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /// @dev Rejects accidental BNB transfers — use buyTokensWithNative() instead
    receive() external payable {
        revert Presale__InvalidNativePayment();
    }

    /// @notice Configure a presale round
    /// @param roundId Round number (1–3)
    /// @param allocation Total WAVE tokens available in this round (in wei)
    function setRound(
        uint256 roundId,
        uint256 allocation
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (roundId == 0 || roundId > ROUND_COUNT) revert Presale__InvalidRound(roundId);
        if (allocation == 0) revert Presale__ZeroAmount();

        uint256 currentSold = rounds[roundId].sold;
        if (allocation < currentSold) revert Presale__AllocationBelowSold(allocation, currentSold);

        rounds[roundId] = Round({
            allocation: allocation,
            sold: currentSold,
            configured: true
        });

        emit RoundConfigured(roundId, allocation);
    }

    /// @notice Set price per WAVE for a specific payment token in a specific round
    /// @dev Price is in the payment token's native smallest unit per 1 WAVE.
    ///      For USDT (6 dec) at $0.25/WAVE: price = 250_000 (0.25 * 1e6).
    ///      For BNB (18 dec) at $600/BNB, $0.25/WAVE: price = 416_666_666_666_666 (0.25/600 * 1e18).
    /// @param roundId Round number (1–3)
    /// @param paymentToken Payment token address (address(0) for BNB)
    /// @param price Price per WAVE in payment token's native units
    function setTokenPrice(
        uint256 roundId,
        address paymentToken,
        uint256 price
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (roundId == 0 || roundId > ROUND_COUNT) revert Presale__InvalidRound(roundId);
        if (price == 0) revert Presale__ZeroAmount();
        tokenPrices[roundId][paymentToken] = price;
        emit TokenPriceUpdated(roundId, paymentToken, price);
    }

    /// @notice Start the presale — enables token purchases
    function startPresale() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (active) revert Presale__AlreadyInState(true);
        active = true;
        emit PresaleStarted();
    }

    /// @notice Stop the presale — disables token purchases
    function stopPresale() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!active) revert Presale__AlreadyInState(false);
        active = false;
        emit PresaleStopped();
    }

    /// @notice Whitelist or remove a payment token (USDT, USDC, BUSD)
    /// @param token Address of the ERC-20 payment token
    /// @param allowed Whether to accept this token
    function setAcceptedPaymentToken(address token, bool allowed) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (token == address(0)) revert Presale__ZeroAddress();
        acceptedPaymentTokens[token] = allowed;
        emit PaymentTokenUpdated(token, allowed);
    }

    /// @notice Set per-wallet purchase limits
    /// @param minBuy Minimum WAVE tokens per purchase (in wei)
    /// @param maxBuy Maximum WAVE tokens per wallet per round (in wei)
    function setWalletLimits(uint256 minBuy, uint256 maxBuy) external onlyRole(DEFAULT_ADMIN_ROLE) {
        minBuyAmount = minBuy;
        maxBuyAmount = maxBuy;
        emit WalletLimitsUpdated(minBuy, maxBuy);
    }

    /// @notice Set whether a round requires whitelist verification
    /// @param roundId Round number (1–3)
    /// @param required Whether whitelist is required for this round
    function setWhitelistRequired(uint256 roundId, bool required) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (roundId == 0 || roundId > ROUND_COUNT) revert Presale__InvalidRound(roundId);
        whitelistRequired[roundId] = required;
        emit RoundWhitelistToggled(roundId, required);
    }

    /// @notice Add or remove an address from the buyer whitelist
    /// @param buyer Address to whitelist or remove
    /// @param allowed Whether the buyer is allowed
    function setWhitelisted(address buyer, bool allowed) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (buyer == address(0)) revert Presale__ZeroAddress();
        whitelisted[buyer] = allowed;
        emit WhitelistUpdated(buyer, allowed);
    }

    /// @notice Batch whitelist or remove multiple addresses
    /// @param buyers Array of buyer addresses
    /// @param allowed Whether all buyers should be whitelisted or removed
    function batchSetWhitelisted(address[] calldata buyers, bool allowed) external onlyRole(DEFAULT_ADMIN_ROLE) {
        for (uint256 i = 0; i < buyers.length; i++) {
            if (buyers[i] == address(0)) revert Presale__ZeroAddress();
            whitelisted[buyers[i]] = allowed;
            emit WhitelistUpdated(buyers[i], allowed);
        }
    }

    /// @notice Buy WAVE tokens with an accepted ERC-20 stablecoin
    /// @param roundId Presale round (1–3)
    /// @param paymentAmount Amount of payment token to spend
    /// @param paymentToken Address of the payment token
    function buyTokens(uint256 roundId, uint256 paymentAmount, address paymentToken) external nonReentrant whenNotPaused {
        if (!active) revert Presale__NotActive();
        if (paymentAmount == 0) revert Presale__ZeroAmount();
        if (!acceptedPaymentTokens[paymentToken]) revert Presale__PaymentTokenNotAccepted(paymentToken);
        if (whitelistRequired[roundId] && !whitelisted[msg.sender]) revert Presale__NotWhitelisted(msg.sender);

        uint256 waveAmount = _calculateWaveAmount(roundId, paymentAmount, paymentToken);
        _validateAndRecordPurchase(roundId, waveAmount, msg.sender);

        IERC20(paymentToken).safeTransferFrom(msg.sender, address(this), paymentAmount);
        presaleVesting.createVestingSchedule(msg.sender, waveAmount, roundId);

        emit TokensPurchased(msg.sender, roundId, paymentToken, paymentAmount, waveAmount);
    }

    /// @notice Buy WAVE tokens with BNB
    /// @param roundId Presale round (1–3)
    function buyTokensWithNative(uint256 roundId) external payable nonReentrant whenNotPaused {
        if (!active) revert Presale__NotActive();
        if (msg.value == 0) revert Presale__InvalidNativePayment();
        if (whitelistRequired[roundId] && !whitelisted[msg.sender]) revert Presale__NotWhitelisted(msg.sender);

        uint256 waveAmount = _calculateWaveAmount(roundId, msg.value, address(0));
        _validateAndRecordPurchase(roundId, waveAmount, msg.sender);

        presaleVesting.createVestingSchedule(msg.sender, waveAmount, roundId);

        emit TokensPurchased(msg.sender, roundId, address(0), msg.value, waveAmount);
    }

    /// @notice Admin withdraws collected payment tokens
    /// @param token Address of the token to withdraw (use address(0) for BNB)
    /// @param amount Amount to withdraw
    /// @param recipient Address to receive the funds
    function withdrawFunds(address token, uint256 amount, address recipient) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (recipient == address(0)) revert Presale__ZeroAddress();
        if (amount == 0) revert Presale__ZeroAmount();

        if (token == address(0)) {
            uint256 balance = address(this).balance;
            if (amount > balance) revert Presale__InsufficientBalance(amount, balance);
            (bool success,) = recipient.call{value: amount}("");
            if (!success) revert Presale__NativeTransferFailed();
        } else {
            uint256 balance = IERC20(token).balanceOf(address(this));
            if (amount > balance) revert Presale__InsufficientBalance(amount, balance);
            IERC20(token).safeTransfer(recipient, amount);
        }

        emit FundsWithdrawn(token, recipient, amount);
    }

    /// @notice Returns round configuration and sold amount
    /// @param roundId Round number (1–3)
    /// @return allocation Total allocation
    /// @return sold Tokens sold
    /// @return remaining Tokens remaining
    /// @return configured Whether the round is configured
    function getRoundInfo(uint256 roundId) external view returns (
        uint256 allocation,
        uint256 sold,
        uint256 remaining,
        bool configured
    ) {
        Round storage r = rounds[roundId];
        return (r.allocation, r.sold, r.allocation - r.sold, r.configured);
    }

    /// @notice Returns a buyer's total purchase in a specific round
    /// @param buyer Buyer address
    /// @param roundId Round number (1–3)
    /// @return WAVE tokens purchased (in wei)
    function getBuyerInfo(address buyer, uint256 roundId) external view returns (uint256) {
        return buyerPurchases[buyer][roundId];
    }

    /// @notice Pause all state-changing operations — admin only
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause all operations — admin only
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @dev Calculates WAVE token amount using per-token pricing.
    ///      waveAmount = (paymentAmount * 1e18) / tokenPrice
    ///      tokenPrice is in the payment token's native smallest unit per 1 WAVE.
    function _calculateWaveAmount(uint256 roundId, uint256 paymentAmount, address paymentToken) internal view returns (uint256) {
        if (roundId == 0 || roundId > ROUND_COUNT) revert Presale__InvalidRound(roundId);
        Round storage r = rounds[roundId];
        if (!r.configured) revert Presale__RoundNotConfigured(roundId);

        uint256 price = tokenPrices[roundId][paymentToken];
        if (price == 0) revert Presale__TokenPriceNotSet(roundId, paymentToken);

        return (paymentAmount * 1e18) / price;
    }

    /// @dev Validates purchase against round cap and wallet limits, then records it
    function _validateAndRecordPurchase(uint256 roundId, uint256 waveAmount, address buyer) internal {
        if (waveAmount == 0) revert Presale__ZeroAmount();

        Round storage r = rounds[roundId];
        uint256 available = r.allocation - r.sold;
        if (waveAmount > available) revert Presale__RoundCapExceeded(roundId, waveAmount, available);

        if (minBuyAmount > 0 && waveAmount < minBuyAmount) {
            revert Presale__BelowMinBuy(waveAmount, minBuyAmount);
        }

        uint256 newTotal = buyerPurchases[buyer][roundId] + waveAmount;
        if (maxBuyAmount > 0 && newTotal > maxBuyAmount) {
            revert Presale__ExceedsMaxBuy(newTotal, maxBuyAmount);
        }

        r.sold += waveAmount;
        buyerPurchases[buyer][roundId] = newTotal;
    }
}
