// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

interface IWaveTokenMintable {
    function mint(address to, uint256 amount) external;
}

/// @title Migration — V1-to-WAVE token migration contract
/// @author OneWave
/// @notice Allows holders of a previous token version (V1) to swap for new WAVE tokens
///         within a configurable migration window. Old tokens are burned; new tokens are minted.
/// @dev Requires MIGRATION_ROLE on WaveToken to mint. Old tokens must implement ERC20Burnable.
///      Migration ratio is admin-configurable. Window enforcement prevents migration outside time bounds.
contract Migration is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /// @dev Thrown when a zero address is provided where a valid address is required
    error Migration__ZeroAddress();

    /// @dev Thrown when a zero amount is provided where a positive value is required
    error Migration__ZeroAmount();

    /// @dev Thrown when migration is not currently active
    error Migration__NotActive();

    /// @dev Thrown when migration is already in the requested state
    error Migration__AlreadyInState(bool active);

    /// @dev Thrown when the migration window has not been set yet
    error Migration__WindowNotSet();

    /// @dev Thrown when the current time is outside the migration window
    error Migration__OutsideWindow(uint256 current, uint256 start, uint256 end);

    /// @dev Thrown when setting an invalid migration window (end <= start)
    error Migration__InvalidWindow(uint256 start, uint256 end);

    /// @dev Thrown when the migration ratio has not been set (is zero)
    error Migration__RatioNotSet();

    /// @dev Thrown when trying to withdraw before the migration window has ended
    error Migration__WindowNotEnded();

    /// @dev Thrown when the contract has insufficient token balance for withdrawal
    error Migration__InsufficientBalance(uint256 requested, uint256 available);

    /// @dev Thrown when trying to change configuration while migration is active
    error Migration__ActiveMigration();

    /// @notice Emitted when the migration window is set
    /// @param start Window start timestamp
    /// @param end Window end timestamp
    event MigrationWindowSet(uint256 start, uint256 end);

    /// @notice Emitted when the migration ratio is set
    /// @param numerator Ratio numerator
    /// @param denominator Ratio denominator
    event MigrationRatioSet(uint256 numerator, uint256 denominator);

    /// @notice Emitted when migration is activated
    event MigrationStarted();

    /// @notice Emitted when migration is deactivated
    event MigrationStopped();

    /// @notice Emitted when a user migrates tokens
    /// @param user Address of the migrator
    /// @param oldAmount Amount of old tokens burned
    /// @param newAmount Amount of new WAVE tokens minted
    event Migrated(address indexed user, uint256 oldAmount, uint256 newAmount);

    /// @notice Emitted when admin withdraws remaining tokens after migration ends
    /// @param token Address of the withdrawn token
    /// @param amount Amount withdrawn
    event UnusedTokensWithdrawn(address indexed token, uint256 amount);

    IERC20 public immutable oldToken;
    IWaveTokenMintable public immutable waveToken;

    bool public active;
    uint256 public windowStart;
    uint256 public windowEnd;
    uint256 public ratioNumerator;   // e.g., 1 for 1:1
    uint256 public ratioDenominator; // e.g., 1 for 1:1

    uint256 public totalMigrated; // total old tokens migrated

    /// @notice Deploys the Migration contract
    /// @param _oldToken Address of the V1 token (must be ERC20Burnable)
    /// @param _waveToken Address of the new WAVE token
    constructor(address _oldToken, address _waveToken) {
        if (_oldToken == address(0)) revert Migration__ZeroAddress();
        if (_waveToken == address(0)) revert Migration__ZeroAddress();
        oldToken = IERC20(_oldToken);
        waveToken = IWaveTokenMintable(_waveToken);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /// @notice Set the migration time window — admin only
    /// @param start Start timestamp (unix seconds)
    /// @param end End timestamp (unix seconds)
    function setMigrationWindow(uint256 start, uint256 end) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (active) revert Migration__ActiveMigration();
        if (end <= start) revert Migration__InvalidWindow(start, end);
        windowStart = start;
        windowEnd = end;
        emit MigrationWindowSet(start, end);
    }

    /// @notice Set the migration ratio (oldToken:newToken) — admin only
    /// @param numerator Ratio numerator (new tokens per denominator old tokens)
    /// @param denominator Ratio denominator
    function setMigrationRatio(uint256 numerator, uint256 denominator) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (active) revert Migration__ActiveMigration();
        if (numerator == 0 || denominator == 0) revert Migration__ZeroAmount();
        ratioNumerator = numerator;
        ratioDenominator = denominator;
        emit MigrationRatioSet(numerator, denominator);
    }

    /// @notice Activate migration — admin only
    function startMigration() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (active) revert Migration__AlreadyInState(true);
        active = true;
        emit MigrationStarted();
    }

    /// @notice Deactivate migration — admin only
    function stopMigration() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!active) revert Migration__AlreadyInState(false);
        active = false;
        emit MigrationStopped();
    }

    /// @notice Migrate old tokens for new WAVE tokens
    /// @dev Burns old tokens from the user and mints new WAVE tokens via MIGRATION_ROLE.
    ///      Requires active migration, valid window, and configured ratio.
    /// @param amount Amount of old tokens to migrate
    function migrate(uint256 amount) external nonReentrant whenNotPaused {
        if (amount == 0) revert Migration__ZeroAmount();
        if (!active) revert Migration__NotActive();
        if (windowStart == 0 || windowEnd == 0) revert Migration__WindowNotSet();
        if (block.timestamp < windowStart || block.timestamp > windowEnd) {
            revert Migration__OutsideWindow(block.timestamp, windowStart, windowEnd);
        }
        if (ratioNumerator == 0 || ratioDenominator == 0) revert Migration__RatioNotSet();

        uint256 newAmount = (amount * ratioNumerator) / ratioDenominator;
        if (newAmount == 0) revert Migration__ZeroAmount();

        totalMigrated += amount;

        // Transfer old tokens to this contract, then burn them
        oldToken.safeTransferFrom(msg.sender, address(this), amount);
        ERC20Burnable(address(oldToken)).burn(amount);

        // Mint new WAVE tokens to the user
        waveToken.mint(msg.sender, newAmount);

        emit Migrated(msg.sender, amount, newAmount);
    }

    /// @notice Preview how many WAVE tokens a migration amount would yield
    /// @param amount Amount of old tokens to preview
    /// @return newAmount Amount of WAVE tokens that would be minted
    function previewMigration(uint256 amount) external view returns (uint256 newAmount) {
        if (ratioNumerator == 0 || ratioDenominator == 0) return 0;
        return (amount * ratioNumerator) / ratioDenominator;
    }

    /// @notice Admin withdraws any remaining tokens after migration window ends
    /// @param amount Amount to withdraw
    function withdrawUnusedTokens(uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (amount == 0) revert Migration__ZeroAmount();
        if (windowEnd == 0 || block.timestamp <= windowEnd) revert Migration__WindowNotEnded();

        uint256 balance = oldToken.balanceOf(address(this));
        if (amount > balance) revert Migration__InsufficientBalance(amount, balance);

        oldToken.safeTransfer(msg.sender, amount);
        emit UnusedTokensWithdrawn(address(oldToken), amount);
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
