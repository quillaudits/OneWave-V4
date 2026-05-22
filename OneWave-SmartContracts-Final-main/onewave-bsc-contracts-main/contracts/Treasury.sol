// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title Treasury — Multi-token treasury for the OneWave ecosystem
/// @author OneWave
/// @notice Stores WAVE tokens, stablecoins, and BNB for operational use, reserve allocation,
///         and ecosystem contract funding. Controlled by multisig admin.
/// @dev Supports any ERC-20 token plus native BNB. All withdrawals and transfers use SafeERC20
///      and are protected by ReentrancyGuard.
contract Treasury is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /// @dev Thrown when a zero address is provided where a valid address is required
    error Treasury__ZeroAddress();

    /// @dev Thrown when a zero amount is provided where a positive value is required
    error Treasury__ZeroAmount();

    /// @dev Thrown when attempting to withdraw more than the available balance
    error Treasury__InsufficientBalance(uint256 requested, uint256 available);

    /// @dev Thrown when a native BNB transfer fails
    error Treasury__NativeTransferFailed();

    /// @notice Emitted when ERC-20 tokens are deposited into the treasury
    /// @param token Address of the deposited token
    /// @param from Address that deposited the tokens
    /// @param amount Number of tokens deposited (in wei)
    event Deposited(address indexed token, address indexed from, uint256 amount);

    /// @notice Emitted when native BNB is deposited into the treasury
    /// @param from Address that sent the BNB
    /// @param amount BNB amount in wei
    event NativeDeposited(address indexed from, uint256 amount);

    /// @notice Emitted when tokens are withdrawn from the treasury
    /// @param token Address of the withdrawn token (address(0) for BNB)
    /// @param recipient Recipient of the withdrawal
    /// @param amount Number of tokens withdrawn (in wei)
    event Withdrawn(address indexed token, address indexed recipient, uint256 amount);

    /// @notice Emitted when admin approves a spender for a specific token
    /// @param token Address of the token
    /// @param spender Approved spender address
    /// @param amount Approved amount (in wei)
    event SpendingApproved(address indexed token, address indexed spender, uint256 amount);

    /// @notice Emitted when admin funds another ecosystem contract with WAVE tokens
    /// @param contractAddress Address of the funded contract
    /// @param amount Number of WAVE tokens sent (in wei)
    event ContractFunded(address indexed contractAddress, uint256 amount);

    IERC20 public immutable waveToken;

    /// @notice Deploys the Treasury with the WAVE token address and assigns admin role
    /// @param _waveToken Address of the WAVE ERC-20 token contract
    constructor(address _waveToken) {
        if (_waveToken == address(0)) revert Treasury__ZeroAddress();
        waveToken = IERC20(_waveToken);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /// @notice Receive native BNB
    receive() external payable {
        emit NativeDeposited(msg.sender, msg.value);
    }

    /// @notice Deposit any ERC-20 token into the treasury
    /// @param token Address of the ERC-20 token
    /// @param amount Number of tokens to deposit (in wei)
    function deposit(address token, uint256 amount) external nonReentrant whenNotPaused {
        if (token == address(0)) revert Treasury__ZeroAddress();
        if (amount == 0) revert Treasury__ZeroAmount();

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        emit Deposited(token, msg.sender, amount);
    }

    /// @notice Withdraw tokens or BNB from the treasury — admin only
    /// @param token Address of the token (address(0) for BNB)
    /// @param recipient Recipient address
    /// @param amount Amount to withdraw (in wei)
    function withdraw(address token, address recipient, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant whenNotPaused {
        if (recipient == address(0)) revert Treasury__ZeroAddress();
        if (amount == 0) revert Treasury__ZeroAmount();

        if (token == address(0)) {
            uint256 balance = address(this).balance;
            if (amount > balance) revert Treasury__InsufficientBalance(amount, balance);
            (bool success,) = recipient.call{value: amount}("");
            if (!success) revert Treasury__NativeTransferFailed();
        } else {
            uint256 balance = IERC20(token).balanceOf(address(this));
            if (amount > balance) revert Treasury__InsufficientBalance(amount, balance);
            IERC20(token).safeTransfer(recipient, amount);
        }

        emit Withdrawn(token, recipient, amount);
    }

    /// @notice Approve a spender to spend tokens held by the treasury — admin only
    /// @param token Address of the ERC-20 token
    /// @param spender Address to approve
    /// @param amount Allowance amount (in wei)
    function approveSpending(address token, address spender, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant whenNotPaused {
        if (token == address(0)) revert Treasury__ZeroAddress();
        if (spender == address(0)) revert Treasury__ZeroAddress();

        IERC20(token).forceApprove(spender, amount);
        emit SpendingApproved(token, spender, amount);
    }

    /// @notice Send WAVE tokens to another ecosystem contract — admin only
    /// @param contractAddress Address of the target contract
    /// @param amount Number of WAVE tokens to send (in wei)
    function fundContract(address contractAddress, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant whenNotPaused {
        if (contractAddress == address(0)) revert Treasury__ZeroAddress();
        if (amount == 0) revert Treasury__ZeroAmount();

        uint256 balance = waveToken.balanceOf(address(this));
        if (amount > balance) revert Treasury__InsufficientBalance(amount, balance);

        waveToken.safeTransfer(contractAddress, amount);
        emit ContractFunded(contractAddress, amount);
    }

    /// @notice Returns the treasury balance of a specific token
    /// @param token Address of the token (address(0) for BNB)
    /// @return Balance in wei
    function getTreasuryBalance(address token) external view returns (uint256) {
        if (token == address(0)) {
            return address(this).balance;
        }
        return IERC20(token).balanceOf(address(this));
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
