// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title Staking — WAVE token staking with reward accrual
/// @author OneWave
/// @notice Allows users to stake WAVE tokens and earn rewards from the staking pool (45M WAVE over 60 months).
///         Rewards are funded externally by RewardDistributor.
/// @dev Uses a reward-per-token accumulator for O(1) reward calculation per user.
///      Precision is maintained with 1e18 scaling on rewardPerTokenStored.
///      Reward accrual stops at rewardEndTime to prevent insolvency.
///      Lock timer only resets on first stake, not on top-ups.
///      Emergency withdraw updates global reward state.
///      Solvency check ensures reward obligations don't exceed available balance.
///      Lock duration capped at MAX_LOCK_DURATION to prevent admin griefing.
contract Staking is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /// @dev Thrown when a zero amount is provided where a positive value is required
    error Staking__ZeroAmount();

    /// @dev Thrown when attempting to unstake more than the user's staked balance
    error Staking__InsufficientStake(uint256 requested, uint256 available);

    /// @dev Thrown when attempting to unstake before the lock duration expires
    error Staking__StillLocked(uint256 unlockTime);

    /// @dev Thrown when claiming with zero pending rewards
    error Staking__NoRewards();

    /// @dev Thrown when a zero address is provided
    error Staking__ZeroAddress();

    /// @dev Thrown when reward rate exceeds MAX_REWARD_RATE
    error Staking__RewardRateTooHigh(uint256 rate, uint256 maxRate);

    /// @dev Thrown when lock duration exceeds MAX_LOCK_DURATION
    error Staking__LockDurationTooLong(uint256 duration, uint256 maxDuration);

    /// @dev Thrown when setting a non-zero reward rate without a reward end time
    error Staking__EndTimeNotSet();

    /// @dev Thrown when reward obligations would exceed available reward balance
    error Staking__InsufficientRewardBalance(uint256 required, uint256 available);

    /// @notice Emitted when a user stakes WAVE tokens
    /// @param user Address of the staker
    /// @param amount Number of WAVE tokens staked (in wei)
    event Staked(address indexed user, uint256 amount);

    /// @notice Emitted when a user unstakes WAVE tokens
    /// @param user Address of the staker
    /// @param amount Number of WAVE tokens unstaked (in wei)
    event Unstaked(address indexed user, uint256 amount);

    /// @notice Emitted when a user claims accumulated rewards
    /// @param user Address of the claimer
    /// @param amount Number of WAVE reward tokens claimed (in wei)
    event RewardsClaimed(address indexed user, uint256 amount);

    /// @notice Emitted when a user performs emergency withdrawal (forfeits rewards)
    /// @param user Address of the withdrawer
    /// @param amount Number of WAVE tokens withdrawn (in wei)
    event EmergencyWithdrawn(address indexed user, uint256 amount);

    /// @notice Emitted when admin updates the reward rate
    /// @param newRate New reward rate in WAVE per second (in wei)
    event RewardRateUpdated(uint256 newRate);

    /// @notice Emitted when admin updates the lock duration
    /// @param newDuration New minimum lock period in seconds
    event LockDurationUpdated(uint256 newDuration);

    /// @notice Emitted when reward tokens are deposited into the contract
    /// @param from Address that deposited rewards
    /// @param amount Number of WAVE tokens deposited (in wei)
    event RewardsDeposited(address indexed from, uint256 amount);

    /// @notice Emitted when admin sets the reward end time
    /// @param endTime Timestamp after which rewards stop accruing
    event RewardEndTimeUpdated(uint256 endTime);

    /// @dev Max reward rate: ~14.26 WAVE/sec = 45M WAVE / 60 months (entire pool over minimum period)
    uint256 public constant MAX_REWARD_RATE = 15 * 1e18;

    /// @dev Maximum lock duration: 365 days — prevents admin from griefing stakers
    uint256 public constant MAX_LOCK_DURATION = 365 days;

    IERC20 public immutable waveToken;

    uint256 public rewardRate;       // WAVE per second (in wei)
    uint256 public rewardEndTime;    // timestamp after which rewards stop accruing
    uint256 public lockDuration;     // minimum lock period in seconds
    uint256 public totalStaked;
    uint256 public rewardPerTokenStored;
    uint256 public lastUpdateTime;
    uint256 public totalRewardsReserved; // sum of all users' crystallized unclaimed rewards

    struct UserInfo {
        uint256 stakedAmount;
        uint256 rewardDebt;      // rewardPerTokenStored snapshot at last action
        uint256 pendingRewards;  // accumulated but unclaimed rewards
        uint256 stakeTimestamp;  // first stake time for lock enforcement
    }

    mapping(address => UserInfo) public userInfo;

    /// @notice Deploys the Staking contract with the WAVE token address
    /// @param _waveToken Address of the WAVE ERC-20 token contract
    constructor(address _waveToken) {
        if (_waveToken == address(0)) revert Staking__ZeroAddress();
        waveToken = IERC20(_waveToken);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        lastUpdateTime = block.timestamp;
    }

    /// @notice Stake WAVE tokens
    /// @dev Lock timer only starts on first stake; top-ups do not reset it
    /// @param amount Number of WAVE tokens to stake (in wei)
    function stake(uint256 amount) external nonReentrant whenNotPaused {
        if (amount == 0) revert Staking__ZeroAmount();

        _updateReward(msg.sender);

        UserInfo storage user = userInfo[msg.sender];
        // Only set stakeTimestamp on first stake (when balance was 0)
        if (user.stakedAmount == 0) {
            user.stakeTimestamp = block.timestamp;
        }
        user.stakedAmount += amount;
        totalStaked += amount;

        waveToken.safeTransferFrom(msg.sender, address(this), amount);
        emit Staked(msg.sender, amount);
    }

    /// @notice Unstake WAVE tokens (must be past lock duration)
    /// @param amount Number of WAVE tokens to unstake (in wei)
    function unstake(uint256 amount) external nonReentrant whenNotPaused {
        if (amount == 0) revert Staking__ZeroAmount();

        UserInfo storage user = userInfo[msg.sender];
        if (amount > user.stakedAmount) revert Staking__InsufficientStake(amount, user.stakedAmount);

        uint256 unlockTime = user.stakeTimestamp + lockDuration;
        if (block.timestamp < unlockTime) revert Staking__StillLocked(unlockTime);

        _updateReward(msg.sender);

        user.stakedAmount -= amount;
        totalStaked -= amount;

        waveToken.safeTransfer(msg.sender, amount);
        emit Unstaked(msg.sender, amount);
    }

    /// @notice Claim accumulated WAVE rewards
    function claimRewards() external nonReentrant whenNotPaused {
        _updateReward(msg.sender);

        uint256 reward = userInfo[msg.sender].pendingRewards;
        if (reward == 0) revert Staking__NoRewards();

        userInfo[msg.sender].pendingRewards = 0;
        totalRewardsReserved -= reward;
        waveToken.safeTransfer(msg.sender, reward);
        emit RewardsClaimed(msg.sender, reward);
    }

    /// @notice Emergency withdraw: forfeits all unclaimed rewards, bypasses lock
    /// @dev Updates global reward state before withdrawal to prevent reward inflation
    function emergencyWithdraw() external nonReentrant {
        _updateGlobalReward();

        UserInfo storage user = userInfo[msg.sender];
        uint256 amount = user.stakedAmount;
        if (amount == 0) revert Staking__ZeroAmount();

        totalRewardsReserved -= user.pendingRewards;
        user.stakedAmount = 0;
        user.pendingRewards = 0;
        user.rewardDebt = rewardPerTokenStored;
        totalStaked -= amount;

        waveToken.safeTransfer(msg.sender, amount);
        emit EmergencyWithdrawn(msg.sender, amount);
    }

    /// @notice Deposit reward tokens into the staking contract
    /// @dev Called by RewardDistributor to fund the reward pool
    /// @param amount Number of WAVE tokens to deposit as rewards (in wei)
    function depositRewards(uint256 amount) external nonReentrant {
        if (amount == 0) revert Staking__ZeroAmount();
        waveToken.safeTransferFrom(msg.sender, address(this), amount);
        emit RewardsDeposited(msg.sender, amount);
    }

    /// @notice Set the reward rate — admin only
    /// @dev Capped at MAX_REWARD_RATE. Requires rewardEndTime to be set first. Validates solvency.
    /// @param rate New reward rate in WAVE per second (in wei)
    function setRewardRate(uint256 rate) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (rate > MAX_REWARD_RATE) revert Staking__RewardRateTooHigh(rate, MAX_REWARD_RATE);
        if (rate > 0 && rewardEndTime == 0) revert Staking__EndTimeNotSet();
        _updateGlobalReward();
        if (rate > 0) {
            _checkSolvency(rate, rewardEndTime);
        }
        rewardRate = rate;
        emit RewardRateUpdated(rate);
    }

    /// @notice Set the reward end time — admin only
    /// @dev Rewards stop accruing after this timestamp. Validates solvency.
    /// @param endTime Unix timestamp after which no more rewards accrue
    function setRewardEndTime(uint256 endTime) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _updateGlobalReward();
        if (rewardRate > 0 && endTime > block.timestamp) {
            _checkSolvency(rewardRate, endTime);
        }
        rewardEndTime = endTime;
        emit RewardEndTimeUpdated(endTime);
    }

    /// @notice Set minimum lock duration — admin only
    /// @dev Capped at MAX_LOCK_DURATION to prevent admin griefing stakers
    /// @param duration Lock period in seconds
    function setLockDuration(uint256 duration) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (duration > MAX_LOCK_DURATION) revert Staking__LockDurationTooLong(duration, MAX_LOCK_DURATION);
        lockDuration = duration;
        emit LockDurationUpdated(duration);
    }

    /// @notice Returns pending (unclaimed) reward amount for a user
    /// @param user Address to query
    /// @return Pending WAVE rewards (in wei)
    function getPendingRewards(address user) external view returns (uint256) {
        UserInfo storage u = userInfo[user];
        uint256 currentRewardPerToken = _currentRewardPerToken();
        uint256 accruedSinceLastAction = (u.stakedAmount * (currentRewardPerToken - u.rewardDebt)) / 1e18;
        return u.pendingRewards + accruedSinceLastAction;
    }

    /// @notice Returns a user's staked balance
    /// @param user Address to query
    /// @return Staked WAVE tokens (in wei)
    function getStakedAmount(address user) external view returns (uint256) {
        return userInfo[user].stakedAmount;
    }

    /// @notice Pause all state-changing operations — admin only
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause all operations — admin only
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @dev Validates that future reward obligations won't exceed available reward balance.
    ///      Subtracts totalStaked (principal) and totalRewardsReserved (crystallized unclaimed rewards)
    ///      from the contract balance to determine what's truly available for future emissions.
    function _checkSolvency(uint256 rate, uint256 endTime) internal view {
        if (endTime <= block.timestamp) return;
        uint256 remainingTime = endTime - block.timestamp;
        uint256 requiredRewards = remainingTime * rate;
        uint256 balance = waveToken.balanceOf(address(this));
        uint256 obligations = totalStaked + totalRewardsReserved;
        uint256 availableRewards = balance > obligations ? balance - obligations : 0;
        if (requiredRewards > availableRewards) {
            revert Staking__InsufficientRewardBalance(requiredRewards, availableRewards);
        }
    }

    /// @dev Updates global reward accumulator and user-specific pending rewards
    function _updateReward(address account) internal {
        _updateGlobalReward();
        UserInfo storage user = userInfo[account];
        uint256 newReward = (user.stakedAmount * (rewardPerTokenStored - user.rewardDebt)) / 1e18;
        user.pendingRewards += newReward;
        totalRewardsReserved += newReward;
        user.rewardDebt = rewardPerTokenStored;
    }

    /// @dev Updates the global rewardPerTokenStored accumulator
    function _updateGlobalReward() internal {
        rewardPerTokenStored = _currentRewardPerToken();
        lastUpdateTime = _lastRewardTime();
    }

    /// @dev Returns the effective last reward timestamp, capped at rewardEndTime
    function _lastRewardTime() internal view returns (uint256) {
        if (rewardEndTime == 0 || block.timestamp <= rewardEndTime) {
            return block.timestamp;
        }
        return rewardEndTime;
    }

    /// @dev Calculates the current reward per token value including unprocessed time
    ///      Rewards stop accruing at rewardEndTime to prevent insolvency
    function _currentRewardPerToken() internal view returns (uint256) {
        if (totalStaked == 0) {
            return rewardPerTokenStored;
        }
        uint256 effectiveTime = _lastRewardTime();
        if (effectiveTime <= lastUpdateTime) {
            return rewardPerTokenStored;
        }
        uint256 timeElapsed = effectiveTime - lastUpdateTime;
        return rewardPerTokenStored + (timeElapsed * rewardRate * 1e18) / totalStaked;
    }
}
