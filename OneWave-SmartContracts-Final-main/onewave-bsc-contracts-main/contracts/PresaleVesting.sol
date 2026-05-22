// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title PresaleVesting — Vesting manager for OneWave presale token allocations
/// @author OneWave
/// @notice Manages vesting schedules for presale investors across 3 rounds with different cliff/unlock terms
/// @dev PRESALE_ROLE restricts schedule creation to the Presale contract only. Tokens must be
///      deposited into this contract before claims succeed. Uses linear vesting after cliff.
///      Per-round allocation caps provide defense-in-depth against PRESALE_ROLE compromise.
contract PresaleVesting is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /// @dev Thrown when a zero address is provided where a valid address is required
    error PresaleVesting__ZeroAddress();

    /// @dev Thrown when a zero amount is provided where a positive value is required
    error PresaleVesting__ZeroAmount();

    /// @dev Thrown when attempting to set TGE time to zero
    error PresaleVesting__InvalidTimestamp();

    /// @dev Thrown when TGE time has already been set and cannot be changed
    error PresaleVesting__TGEAlreadySet();

    /// @dev Thrown when claiming before TGE time is set or reached
    error PresaleVesting__TGENotStarted();

    /// @dev Thrown when a round ID is outside the valid range (1–3)
    error PresaleVesting__InvalidRound(uint256 roundId);

    /// @dev Thrown when creating a vesting for a round that hasn't been configured yet
    error PresaleVesting__RoundNotConfigured(uint256 roundId);

    /// @dev Thrown when a beneficiary already has a vesting schedule for a given round
    error PresaleVesting__DuplicateVesting(address beneficiary, uint256 roundId);

    /// @dev Thrown when no tokens are available to claim (already claimed or still locked)
    error PresaleVesting__NothingToClaim();

    /// @dev Thrown when a user has no vesting schedules
    error PresaleVesting__NoVesting();

    /// @dev Thrown when trying to change round config after schedules already exist for that round
    error PresaleVesting__RoundConfigLocked(uint256 roundId);

    /// @dev Thrown when vesting creation would exceed the round's allocation cap
    error PresaleVesting__RoundCapExceeded(uint256 roundId, uint256 requested, uint256 available);

    /// @notice Emitted when the admin sets the TGE timestamp
    /// @param timestamp The TGE time in unix seconds
    event TGETimeSet(uint256 timestamp);

    /// @notice Emitted when a round's vesting configuration is set or updated
    /// @param roundId Presale round (1–3)
    /// @param tgeUnlockBps TGE unlock in basis points
    /// @param cliffDuration Cliff period in seconds
    /// @param vestingDuration Linear vesting period in seconds after cliff
    event RoundConfigured(uint256 indexed roundId, uint256 tgeUnlockBps, uint256 cliffDuration, uint256 vestingDuration);

    /// @notice Emitted when a vesting schedule is created for a presale buyer
    /// @param beneficiary Address receiving the vesting
    /// @param amount Total tokens in the vesting (in wei)
    /// @param roundId Presale round (1–3)
    event VestingScheduleCreated(address indexed beneficiary, uint256 amount, uint256 roundId);

    /// @notice Emitted when a beneficiary claims vested tokens
    /// @param beneficiary Address claiming the tokens
    /// @param amount Number of tokens claimed (in wei)
    event TokensClaimed(address indexed beneficiary, uint256 amount);

    /// @notice Emitted when a round allocation cap is set
    /// @param roundId Presale round (1–3)
    /// @param allocation Maximum WAVE tokens for this round
    event RoundAllocationSet(uint256 indexed roundId, uint256 allocation);

    bytes32 public constant PRESALE_ROLE = keccak256("PRESALE_ROLE");
    uint256 public constant ROUND_COUNT = 3;

    struct RoundConfig {
        uint256 tgeUnlockBps;    // basis points (10000 = 100%)
        uint256 cliffDuration;   // seconds after TGE
        uint256 vestingDuration; // seconds of linear vesting after cliff
        bool configured;
    }

    struct VestingSchedule {
        uint256 amount;
        uint256 roundId;
        uint256 claimed;
    }

    IERC20 public immutable waveToken;
    uint256 public tgeTime;

    mapping(uint256 => RoundConfig) public roundConfigs;
    mapping(address => VestingSchedule[]) internal _vestingSchedules;
    mapping(address => mapping(uint256 => bool)) internal _hasVesting;
    mapping(uint256 => bool) internal _roundHasSchedules; // locks config after first schedule
    mapping(uint256 => uint256) public roundAllocations; // max WAVE per round
    mapping(uint256 => uint256) public roundAllocated; // WAVE allocated so far per round

    /// @notice Deploys PresaleVesting with the WAVE token address and assigns admin role
    /// @param _waveToken Address of the WAVE ERC-20 token contract
    constructor(address _waveToken) {
        if (_waveToken == address(0)) revert PresaleVesting__ZeroAddress();
        waveToken = IERC20(_waveToken);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /// @notice Set the TGE timestamp — can only be called once
    /// @param timestamp The TGE time in unix seconds
    function setTGETime(uint256 timestamp) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (tgeTime != 0) revert PresaleVesting__TGEAlreadySet();
        if (timestamp == 0) revert PresaleVesting__InvalidTimestamp();
        if (timestamp < block.timestamp) revert PresaleVesting__InvalidTimestamp();
        tgeTime = timestamp;
        emit TGETimeSet(timestamp);
    }

    /// @notice Configure vesting terms for a presale round
    /// @param roundId Presale round (1–3)
    /// @param tgeUnlockBps Percentage unlocked at TGE in basis points (1000 = 10%)
    /// @param cliffDuration Cliff period in seconds after TGE
    /// @param vestingDuration Linear vesting duration in seconds after cliff
    function setRoundVestingConfig(
        uint256 roundId,
        uint256 tgeUnlockBps,
        uint256 cliffDuration,
        uint256 vestingDuration
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (roundId == 0 || roundId > ROUND_COUNT) revert PresaleVesting__InvalidRound(roundId);
        if (_roundHasSchedules[roundId]) revert PresaleVesting__RoundConfigLocked(roundId);
        roundConfigs[roundId] = RoundConfig({
            tgeUnlockBps: tgeUnlockBps,
            cliffDuration: cliffDuration,
            vestingDuration: vestingDuration,
            configured: true
        });
        emit RoundConfigured(roundId, tgeUnlockBps, cliffDuration, vestingDuration);
    }

    /// @notice Set the maximum WAVE allocation for a round (defense-in-depth cap)
    /// @dev If set to 0, no cap is enforced. Cannot be set below already-allocated amount.
    /// @param roundId Presale round (1–3)
    /// @param allocation Maximum WAVE tokens allocatable to this round (in wei)
    function setRoundAllocation(uint256 roundId, uint256 allocation) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (roundId == 0 || roundId > ROUND_COUNT) revert PresaleVesting__InvalidRound(roundId);
        roundAllocations[roundId] = allocation;
        emit RoundAllocationSet(roundId, allocation);
    }

    /// @notice Create a vesting schedule for a presale buyer — restricted to PRESALE_ROLE
    /// @dev Only the Presale contract should call this. One schedule per user per round.
    /// @param beneficiary Address of the buyer
    /// @param amount Total WAVE tokens purchased (in wei)
    /// @param roundId Presale round (1–3)
    function createVestingSchedule(
        address beneficiary,
        uint256 amount,
        uint256 roundId
    ) external onlyRole(PRESALE_ROLE) whenNotPaused {
        if (beneficiary == address(0)) revert PresaleVesting__ZeroAddress();
        if (amount == 0) revert PresaleVesting__ZeroAmount();
        if (roundId == 0 || roundId > ROUND_COUNT) revert PresaleVesting__InvalidRound(roundId);
        if (!roundConfigs[roundId].configured) revert PresaleVesting__RoundNotConfigured(roundId);
        if (_hasVesting[beneficiary][roundId]) revert PresaleVesting__DuplicateVesting(beneficiary, roundId);

        // Enforce per-round allocation cap (defense-in-depth)
        if (roundAllocations[roundId] > 0) {
            uint256 available = roundAllocations[roundId] - roundAllocated[roundId];
            if (amount > available) revert PresaleVesting__RoundCapExceeded(roundId, amount, available);
            roundAllocated[roundId] += amount;
        }

        _hasVesting[beneficiary][roundId] = true;
        _roundHasSchedules[roundId] = true;
        _vestingSchedules[beneficiary].push(VestingSchedule({
            amount: amount,
            roundId: roundId,
            claimed: 0
        }));

        emit VestingScheduleCreated(beneficiary, amount, roundId);
    }

    /// @notice Claim all available vested tokens across all rounds
    /// @dev Aggregates claimable amounts, updates state, then transfers once (CEI pattern)
    function claim() external nonReentrant whenNotPaused {
        if (tgeTime == 0 || block.timestamp < tgeTime) revert PresaleVesting__TGENotStarted();

        VestingSchedule[] storage schedules = _vestingSchedules[msg.sender];
        if (schedules.length == 0) revert PresaleVesting__NoVesting();

        uint256 totalClaimable;
        for (uint256 i = 0; i < schedules.length; i++) {
            uint256 claimable = _calculateClaimable(schedules[i]);
            if (claimable > 0) {
                schedules[i].claimed += claimable;
                totalClaimable += claimable;
            }
        }

        if (totalClaimable == 0) revert PresaleVesting__NothingToClaim();
        waveToken.safeTransfer(msg.sender, totalClaimable);
        emit TokensClaimed(msg.sender, totalClaimable);
    }

    /// @notice Returns the total claimable amount for a user across all rounds
    /// @param user Address to query
    /// @return Total claimable WAVE tokens (in wei)
    function getClaimableAmount(address user) external view returns (uint256) {
        if (tgeTime == 0 || block.timestamp < tgeTime) return 0;
        VestingSchedule[] storage schedules = _vestingSchedules[user];
        uint256 total;
        for (uint256 i = 0; i < schedules.length; i++) {
            total += _calculateClaimable(schedules[i]);
        }
        return total;
    }

    /// @notice Returns all vesting schedules for a user
    /// @param user Address to query
    /// @return Array of VestingSchedule structs
    function getUserVesting(address user) external view returns (VestingSchedule[] memory) {
        return _vestingSchedules[user];
    }

    /// @notice Pause all state-changing operations — admin only
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause all operations — admin only
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @dev Calculates claimable amount for a single vesting schedule based on elapsed time.
    ///      TGE amount is always available after TGE. After cliff, remaining tokens vest linearly.
    function _calculateClaimable(VestingSchedule storage schedule) internal view returns (uint256) {
        RoundConfig storage config = roundConfigs[schedule.roundId];
        uint256 totalAmount = schedule.amount;
        uint256 tgeAmount = (totalAmount * config.tgeUnlockBps) / 10000;

        if (config.vestingDuration == 0) {
            return tgeAmount > schedule.claimed ? tgeAmount - schedule.claimed : 0;
        }

        uint256 elapsed = block.timestamp - tgeTime;

        if (elapsed < config.cliffDuration) {
            return tgeAmount > schedule.claimed ? tgeAmount - schedule.claimed : 0;
        }

        uint256 timeAfterCliff = elapsed - config.cliffDuration;
        uint256 vestedAmount;

        if (timeAfterCliff >= config.vestingDuration) {
            vestedAmount = totalAmount;
        } else {
            uint256 vestableAmount = totalAmount - tgeAmount;
            vestedAmount = tgeAmount + (vestableAmount * timeAfterCliff / config.vestingDuration);
        }

        return vestedAmount > schedule.claimed ? vestedAmount - schedule.claimed : 0;
    }
}
