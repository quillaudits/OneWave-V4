// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

interface IStaking {
    function depositRewards(uint256 amount) external;
}

/// @title RewardDistributor — Reward funding and distribution hub for OneWave ecosystem
/// @author OneWave
/// @notice Receives WAVE tokens from TokenLocker (staking & rewards category), funds the Staking
///         contract, and handles campaign/community reward distributions
/// @dev Only authorized sources may deposit rewards. Admin controls all distributions.
///      Batch distribution is bounded to MAX_BATCH_SIZE to prevent gas limit issues.
contract RewardDistributor is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /// @dev Thrown when a zero address is provided where a valid address is required
    error RewardDistributor__ZeroAddress();

    /// @dev Thrown when a zero amount is provided where a positive value is required
    error RewardDistributor__ZeroAmount();

    /// @dev Thrown when a non-authorized source tries to deposit rewards
    error RewardDistributor__UnauthorizedSource(address source);

    /// @dev Thrown when input arrays have different lengths in batch operations
    error RewardDistributor__LengthMismatch();

    /// @dev Thrown when empty arrays are passed to batch operations
    error RewardDistributor__EmptyArrays();

    /// @dev Thrown when batch size exceeds MAX_BATCH_SIZE
    error RewardDistributor__MaxBatchSizeExceeded(uint256 size, uint256 maxSize);

    /// @dev Thrown when attempting to distribute more than the contract's WAVE balance
    error RewardDistributor__InsufficientBalance(uint256 requested, uint256 available);

    /// @notice Emitted when an authorized source deposits WAVE rewards
    /// @param source Address that deposited the rewards
    /// @param amount Number of WAVE tokens deposited (in wei)
    event RewardsDeposited(address indexed source, uint256 amount);

    /// @notice Emitted when admin distributes rewards to a single recipient
    /// @param recipient Address receiving the reward
    /// @param amount Number of WAVE tokens distributed (in wei)
    event RewardDistributed(address indexed recipient, uint256 amount);

    /// @notice Emitted when admin funds the staking contract with rewards
    /// @param stakingContract Address of the staking contract
    /// @param amount Number of WAVE tokens sent (in wei)
    event StakingFunded(address indexed stakingContract, uint256 amount);

    /// @notice Emitted when an authorized source is added or removed
    /// @param source Address of the source
    /// @param allowed Whether the source is now authorized
    event AuthorizedSourceUpdated(address indexed source, bool allowed);

    /// @notice Emitted when admin withdraws unused reward tokens
    /// @param recipient Address receiving the withdrawn tokens
    /// @param amount Number of WAVE tokens withdrawn (in wei)
    event UnusedRewardsWithdrawn(address indexed recipient, uint256 amount);

    uint256 public constant MAX_BATCH_SIZE = 200;

    IERC20 public immutable waveToken;
    address public stakingContract;

    mapping(address => bool) public authorizedSources;

    /// @notice Deploys the RewardDistributor with the WAVE token and staking contract addresses
    /// @param _waveToken Address of the WAVE ERC-20 token
    /// @param _stakingContract Address of the Staking contract to fund
    constructor(address _waveToken, address _stakingContract) {
        if (_waveToken == address(0)) revert RewardDistributor__ZeroAddress();
        if (_stakingContract == address(0)) revert RewardDistributor__ZeroAddress();
        waveToken = IERC20(_waveToken);
        stakingContract = _stakingContract;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /// @notice Deposit WAVE rewards into this contract — restricted to authorized sources
    /// @param amount Number of WAVE tokens to deposit (in wei)
    function depositRewards(uint256 amount) external nonReentrant whenNotPaused {
        if (amount == 0) revert RewardDistributor__ZeroAmount();
        if (!authorizedSources[msg.sender]) revert RewardDistributor__UnauthorizedSource(msg.sender);

        waveToken.safeTransferFrom(msg.sender, address(this), amount);
        emit RewardsDeposited(msg.sender, amount);
    }

    /// @notice Distribute WAVE rewards to a single recipient — admin only
    /// @param recipient Address to receive the reward
    /// @param amount Number of WAVE tokens to send (in wei)
    function distributeReward(address recipient, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant whenNotPaused {
        if (recipient == address(0)) revert RewardDistributor__ZeroAddress();
        if (amount == 0) revert RewardDistributor__ZeroAmount();

        uint256 balance = waveToken.balanceOf(address(this));
        if (amount > balance) revert RewardDistributor__InsufficientBalance(amount, balance);

        waveToken.safeTransfer(recipient, amount);
        emit RewardDistributed(recipient, amount);
    }

    /// @notice Batch distribute WAVE rewards to multiple recipients — admin only
    /// @param users Array of recipient addresses
    /// @param amounts Array of WAVE amounts (in wei), must match users length
    function batchDistribute(
        address[] calldata users,
        uint256[] calldata amounts
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant whenNotPaused {
        if (users.length != amounts.length) revert RewardDistributor__LengthMismatch();
        if (users.length == 0) revert RewardDistributor__EmptyArrays();
        if (users.length > MAX_BATCH_SIZE) revert RewardDistributor__MaxBatchSizeExceeded(users.length, MAX_BATCH_SIZE);

        uint256 totalAmount;
        for (uint256 i = 0; i < users.length; i++) {
            if (users[i] == address(0)) revert RewardDistributor__ZeroAddress();
            if (amounts[i] == 0) revert RewardDistributor__ZeroAmount();
            totalAmount += amounts[i];
        }

        uint256 balance = waveToken.balanceOf(address(this));
        if (totalAmount > balance) revert RewardDistributor__InsufficientBalance(totalAmount, balance);

        for (uint256 i = 0; i < users.length; i++) {
            waveToken.safeTransfer(users[i], amounts[i]);
            emit RewardDistributed(users[i], amounts[i]);
        }
    }

    /// @notice Fund the staking contract with WAVE reward tokens — admin only
    /// @param amount Number of WAVE tokens to send to the staking contract (in wei)
    function fundStakingContract(uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant whenNotPaused {
        if (amount == 0) revert RewardDistributor__ZeroAmount();

        uint256 balance = waveToken.balanceOf(address(this));
        if (amount > balance) revert RewardDistributor__InsufficientBalance(amount, balance);

        waveToken.forceApprove(stakingContract, amount);
        IStaking(stakingContract).depositRewards(amount);
        emit StakingFunded(stakingContract, amount);
    }

    /// @notice Add or remove an authorized deposit source — admin only
    /// @param source Address to authorize or deauthorize
    /// @param allowed Whether to allow deposits from this source
    function setAuthorizedSource(address source, bool allowed) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (source == address(0)) revert RewardDistributor__ZeroAddress();
        authorizedSources[source] = allowed;
        emit AuthorizedSourceUpdated(source, allowed);
    }

    /// @notice Withdraw unused reward tokens — admin only
    /// @param amount Number of WAVE tokens to withdraw (in wei)
    function withdrawUnusedRewards(uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (amount == 0) revert RewardDistributor__ZeroAmount();

        uint256 balance = waveToken.balanceOf(address(this));
        if (amount > balance) revert RewardDistributor__InsufficientBalance(amount, balance);

        waveToken.safeTransfer(msg.sender, amount);
        emit UnusedRewardsWithdrawn(msg.sender, amount);
    }

    /// @notice Pause all state-changing operations — admin only
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause all operations — admin only
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
