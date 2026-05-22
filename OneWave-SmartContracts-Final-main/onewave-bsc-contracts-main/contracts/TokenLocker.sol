// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title TokenLocker — Non-presale token allocation and vesting manager
/// @author OneWave
/// @notice Manages vesting schedules for 8 allocation categories of the OneWave ecosystem
/// @dev All token transfers use SafeERC20. Category allocations are immutable after deployment.
///      Admin creates vesting schedules; beneficiaries claim linearly after TGE + cliff.
contract TokenLocker is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /// @dev Thrown when a zero address is provided where a valid address is required
    error TokenLocker__ZeroAddress();

    /// @dev Thrown when a zero amount is provided where a positive value is required
    error TokenLocker__ZeroAmount();

    /// @dev Thrown when attempting to set TGE time to zero
    error TokenLocker__InvalidTimestamp();

    /// @dev Thrown when TGE time has already been set and cannot be changed
    error TokenLocker__TGEAlreadySet();

    /// @dev Thrown when a category ID is out of the valid range (0–7)
    error TokenLocker__InvalidCategory(uint256 categoryId);

    /// @dev Thrown when an allocation would exceed the category's total cap
    error TokenLocker__ExceedsCategoryCap(uint256 categoryId, uint256 requested, uint256 available);

    /// @dev Thrown when input arrays have different lengths in batch operations
    error TokenLocker__LengthMismatch();

    /// @dev Thrown when empty arrays are passed to batch operations
    error TokenLocker__EmptyArrays();

    /// @dev Thrown when claiming before TGE time is set or reached
    error TokenLocker__TGENotStarted();

    /// @dev Thrown when a user has no vesting schedules to claim
    error TokenLocker__NoVestings();

    /// @dev Thrown when no tokens are available to claim (already claimed or still locked)
    error TokenLocker__NothingToClaim();

    /// @dev Thrown when referencing a vesting ID that does not exist for a user
    error TokenLocker__InvalidVestingId(uint256 vestingId);

    /// @dev Thrown when distributeFromCategory is called on a category with vesting
    error TokenLocker__CategoryRequiresVesting(uint256 categoryId);

    /// @dev Thrown when airdropDistribution batch exceeds MAX_BATCH_SIZE
    error TokenLocker__MaxBatchSizeExceeded(uint256 size, uint256 maxSize);

    /// @dev Thrown when a beneficiary would exceed MAX_VESTINGS_PER_USER
    error TokenLocker__MaxVestingsExceeded(address user);


    /// @notice Emitted when the admin sets the TGE timestamp
    /// @param timestamp The TGE time in unix seconds
    event TGETimeSet(uint256 timestamp);

    /// @notice Emitted when a vesting schedule is created for a beneficiary
    /// @param beneficiary Address receiving the vesting schedule
    /// @param amount Total tokens in the vesting schedule (in wei)
    /// @param categoryId Allocation category (0–7)
    /// @param vestingId Index in the beneficiary's vesting array
    event VestingCreated(address indexed beneficiary, uint256 amount, uint256 categoryId, uint256 vestingId);

    /// @notice Emitted when a beneficiary claims vested tokens
    /// @param beneficiary Address claiming the tokens
    /// @param amount Number of tokens claimed (in wei)
    /// @param vestingId Index of the vesting schedule claimed from
    event TokensClaimed(address indexed beneficiary, uint256 amount, uint256 vestingId);

    /// @notice Emitted when tokens are directly distributed from a category (e.g. Liquidity)
    /// @param categoryId Allocation category
    /// @param recipient Address receiving the tokens
    /// @param amount Number of tokens distributed (in wei)
    event TokensDistributed(uint256 indexed categoryId, address indexed recipient, uint256 amount);

    /// @notice Emitted when an airdrop vesting schedule is created
    /// @param beneficiary Address receiving the airdrop vesting
    /// @param amount Total tokens in the airdrop (in wei)
    /// @param vestingId Index in the beneficiary's vesting array
    event AirdropCreated(address indexed beneficiary, uint256 amount, uint256 vestingId);

    uint256 public constant STAKING_REWARDS = 0;
    uint256 public constant ECOSYSTEM       = 1;
    uint256 public constant LIQUIDITY       = 2;
    uint256 public constant MARKETING       = 3;
    uint256 public constant TEAM            = 4;
    uint256 public constant ADVISORS        = 5;
    uint256 public constant AIRDROP         = 6;
    uint256 public constant RESERVE         = 7;
    uint256 public constant CATEGORY_COUNT  = 8;
    uint256 public constant MAX_BATCH_SIZE  = 200;
    uint256 public constant MAX_VESTINGS_PER_USER = 50;

    struct Category {
        uint256 totalAllocation;
        uint256 allocated;
        uint256 tgeUnlockBps;    // basis points (10000 = 100%)
        uint256 cliffDuration;   // seconds
        uint256 vestingDuration; // seconds
    }

    struct VestingSchedule {
        uint256 amount;
        uint256 categoryId;
        uint256 claimed;
    }

    IERC20 public immutable waveToken; // WAVE token contract
    uint256 public tgeTime; // TGE timestamp (unix seconds, set once)
    mapping(uint256 => Category) public categories;
    mapping(address => VestingSchedule[]) internal _vestingSchedules;

    /// @notice Deploys the locker, assigns admin role, and initializes all 8 category allocations
    /// @param _waveToken Address of the WAVE ERC-20 token contract
    constructor(address _waveToken) {
        if (_waveToken == address(0)) revert TokenLocker__ZeroAddress();
        waveToken = IERC20(_waveToken);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _initializeCategories();
    }

    /// @notice Set the TGE timestamp — can only be called once
    /// @dev Reverts if already set or if timestamp is zero. Does not require unpaused state
    ///      because this is a one-time configuration step.
    /// @param timestamp The TGE time in unix seconds
    function setTGETime(uint256 timestamp) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (tgeTime != 0) revert TokenLocker__TGEAlreadySet();
        if (timestamp == 0) revert TokenLocker__InvalidTimestamp();
        if (timestamp < block.timestamp) revert TokenLocker__InvalidTimestamp();
        tgeTime = timestamp;
        emit TGETimeSet(timestamp);
    }

    /// @notice Create a vesting schedule for a beneficiary within a category
    /// @param beneficiary Address to receive the vesting schedule
    /// @param amount Total tokens to vest (in wei)
    /// @param categoryId Allocation category (0–7)
    function createVesting(
        address beneficiary,
        uint256 amount,
        uint256 categoryId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused {
        if (beneficiary == address(0)) revert TokenLocker__ZeroAddress();
        if (amount == 0) revert TokenLocker__ZeroAmount();
        if (categoryId >= CATEGORY_COUNT) revert TokenLocker__InvalidCategory(categoryId);
        if (_vestingSchedules[beneficiary].length >= MAX_VESTINGS_PER_USER)
            revert TokenLocker__MaxVestingsExceeded(beneficiary);

        Category storage cat = categories[categoryId];
        uint256 available = cat.totalAllocation - cat.allocated;
        if (amount > available) revert TokenLocker__ExceedsCategoryCap(categoryId, amount, available);

        cat.allocated += amount;
        uint256 vestingId = _vestingSchedules[beneficiary].length;
        _vestingSchedules[beneficiary].push(VestingSchedule({
            amount: amount,
            categoryId: categoryId,
            claimed: 0
        }));

        emit VestingCreated(beneficiary, amount, categoryId, vestingId);
    }

    /// @notice Directly transfer tokens from a category with no vesting (e.g. Liquidity 100% at TGE)
    /// @dev Only allowed for categories with vestingDuration == 0. Categories with vesting schedules
    ///      must use createVesting() to enforce cliff and linear vesting.
    /// @param categoryId Allocation category (0–7)
    /// @param recipient Address to receive the tokens
    /// @param amount Number of tokens to transfer (in wei)
    function distributeFromCategory(
        uint256 categoryId,
        address recipient,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused nonReentrant {
        if (recipient == address(0)) revert TokenLocker__ZeroAddress();
        if (amount == 0) revert TokenLocker__ZeroAmount();
        if (categoryId >= CATEGORY_COUNT) revert TokenLocker__InvalidCategory(categoryId);

        Category storage cat = categories[categoryId];
        if (cat.vestingDuration != 0) revert TokenLocker__CategoryRequiresVesting(categoryId);

        uint256 available = cat.totalAllocation - cat.allocated;
        if (amount > available) revert TokenLocker__ExceedsCategoryCap(categoryId, amount, available);

        cat.allocated += amount;
        waveToken.safeTransfer(recipient, amount);

        emit TokensDistributed(categoryId, recipient, amount);
    }

    /// @notice Batch-create airdrop vesting schedules
    /// @dev Validates all entries before writing state. Admin should batch appropriately
    ///      to stay within block gas limits.
    /// @param users Array of beneficiary addresses
    /// @param amounts Array of token amounts (in wei), must match users length
    function airdropDistribution(
        address[] calldata users,
        uint256[] calldata amounts
    ) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused {
        if (users.length != amounts.length) revert TokenLocker__LengthMismatch();
        if (users.length == 0) revert TokenLocker__EmptyArrays();
        if (users.length > MAX_BATCH_SIZE) revert TokenLocker__MaxBatchSizeExceeded(users.length, MAX_BATCH_SIZE);

        Category storage cat = categories[AIRDROP];
        uint256 totalAmount;

        for (uint256 i = 0; i < users.length; i++) {
            if (users[i] == address(0)) revert TokenLocker__ZeroAddress();
            if (amounts[i] == 0) revert TokenLocker__ZeroAmount();
            totalAmount += amounts[i];
        }

        uint256 available = cat.totalAllocation - cat.allocated;
        if (totalAmount > available) revert TokenLocker__ExceedsCategoryCap(AIRDROP, totalAmount, available);
        cat.allocated += totalAmount;

        for (uint256 i = 0; i < users.length; i++) {
            if (_vestingSchedules[users[i]].length >= MAX_VESTINGS_PER_USER)
                revert TokenLocker__MaxVestingsExceeded(users[i]);
            uint256 vestingId = _vestingSchedules[users[i]].length;
            _vestingSchedules[users[i]].push(VestingSchedule({
                amount: amounts[i],
                categoryId: AIRDROP,
                claimed: 0
            }));
            emit AirdropCreated(users[i], amounts[i], vestingId);
        }
    }

    /// @notice Pause all state-changing operations — admin only
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause all operations — admin only
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Claim all available vested tokens across all schedules
    /// @dev Aggregates claimable amounts, updates claimed state, then transfers once
    function claimVesting() external nonReentrant whenNotPaused {
        if (tgeTime == 0 || block.timestamp < tgeTime) revert TokenLocker__TGENotStarted();

        VestingSchedule[] storage schedules = _vestingSchedules[msg.sender];
        if (schedules.length == 0) revert TokenLocker__NoVestings();

        uint256 totalClaimable;
        for (uint256 i = 0; i < schedules.length; i++) {
            uint256 claimable = _calculateClaimable(schedules[i]);
            if (claimable > 0) {
                schedules[i].claimed += claimable;
                totalClaimable += claimable;
                emit TokensClaimed(msg.sender, claimable, i);
            }
        }

        if (totalClaimable == 0) revert TokenLocker__NothingToClaim();
        waveToken.safeTransfer(msg.sender, totalClaimable);
    }

    /// @notice Claim only airdrop-category vested tokens
    /// @dev Skips non-airdrop schedules. Useful when user has vestings in multiple categories.
    function airdropClaim() external nonReentrant whenNotPaused {
        if (tgeTime == 0 || block.timestamp < tgeTime) revert TokenLocker__TGENotStarted();

        VestingSchedule[] storage schedules = _vestingSchedules[msg.sender];
        if (schedules.length == 0) revert TokenLocker__NoVestings();

        uint256 totalClaimable;
        for (uint256 i = 0; i < schedules.length; i++) {
            if (schedules[i].categoryId == AIRDROP) {
                uint256 claimable = _calculateClaimable(schedules[i]);
                if (claimable > 0) {
                    schedules[i].claimed += claimable;
                    totalClaimable += claimable;
                    emit TokensClaimed(msg.sender, claimable, i);
                }
            }
        }

        if (totalClaimable == 0) revert TokenLocker__NothingToClaim();
        waveToken.safeTransfer(msg.sender, totalClaimable);
    }

    /// @notice Claim vested tokens from a single vesting schedule by ID
    /// @dev Gas-safe alternative to claimVesting for users with many schedules
    /// @param vestingId Index in the caller's vesting array
    function claimSingleVesting(uint256 vestingId) external nonReentrant whenNotPaused {
        if (tgeTime == 0 || block.timestamp < tgeTime) revert TokenLocker__TGENotStarted();

        VestingSchedule[] storage schedules = _vestingSchedules[msg.sender];
        if (vestingId >= schedules.length) revert TokenLocker__InvalidVestingId(vestingId);

        uint256 claimable = _calculateClaimable(schedules[vestingId]);
        if (claimable == 0) revert TokenLocker__NothingToClaim();

        schedules[vestingId].claimed += claimable;
        emit TokensClaimed(msg.sender, claimable, vestingId);
        waveToken.safeTransfer(msg.sender, claimable);
    }

    /// @notice Calculate claimable amount for a specific vesting schedule
    /// @param user Address of the vesting beneficiary
    /// @param vestingId Index in the user's vesting array
    /// @return Claimable amount in wei (0 if TGE has not started)
    function calculateClaimable(address user, uint256 vestingId) external view returns (uint256) {
        if (vestingId >= _vestingSchedules[user].length) revert TokenLocker__InvalidVestingId(vestingId);
        if (tgeTime == 0 || block.timestamp < tgeTime) return 0;
        return _calculateClaimable(_vestingSchedules[user][vestingId]);
    }

    /// @notice Return all vesting schedules for a user
    /// @param user Address to query
    /// @return Array of VestingSchedule structs
    function getVesting(address user) external view returns (VestingSchedule[] memory) {
        return _vestingSchedules[user];
    }

    /// @notice Return category configuration and remaining allocation
    /// @param categoryId Allocation category (0–7)
    /// @return totalAllocation Total tokens allocated to this category
    /// @return allocated Tokens already assigned to vestings or distributions
    /// @return remaining Tokens still available for new vestings
    /// @return tgeUnlockBps TGE unlock percentage in basis points
    /// @return cliffDuration Cliff period in seconds
    /// @return vestingDuration Linear vesting period in seconds
    function getCategoryInfo(uint256 categoryId) external view returns (
        uint256 totalAllocation,
        uint256 allocated,
        uint256 remaining,
        uint256 tgeUnlockBps,
        uint256 cliffDuration,
        uint256 vestingDuration
    ) {
        if (categoryId >= CATEGORY_COUNT) revert TokenLocker__InvalidCategory(categoryId);
        Category storage cat = categories[categoryId];
        return (
            cat.totalAllocation,
            cat.allocated,
            cat.totalAllocation - cat.allocated,
            cat.tgeUnlockBps,
            cat.cliffDuration,
            cat.vestingDuration
        );
    }

    /// @dev Calculates the claimable amount for a single vesting schedule based on elapsed time.
    ///      TGE amount is always available. After cliff, remaining tokens vest linearly.
    function _calculateClaimable(VestingSchedule storage schedule) internal view returns (uint256) {
        Category storage cat = categories[schedule.categoryId];
        uint256 totalAmount = schedule.amount;

        uint256 tgeAmount = (totalAmount * cat.tgeUnlockBps) / 10000;

        if (cat.vestingDuration == 0) {
            return tgeAmount > schedule.claimed ? tgeAmount - schedule.claimed : 0;
        }

        uint256 elapsed = block.timestamp - tgeTime;

        if (elapsed < cat.cliffDuration) {
            return tgeAmount > schedule.claimed ? tgeAmount - schedule.claimed : 0;
        }

        uint256 timeAfterCliff = elapsed - cat.cliffDuration;
        uint256 vestedAmount;

        if (timeAfterCliff >= cat.vestingDuration) {
            vestedAmount = totalAmount;
        } else {
            uint256 vestableAmount = totalAmount - tgeAmount;
            vestedAmount = tgeAmount + (vestableAmount * timeAfterCliff / cat.vestingDuration);
        }

        return vestedAmount > schedule.claimed ? vestedAmount - schedule.claimed : 0;
    }

    /// @dev Initializes the 8 allocation categories with tokenomics from the OneWave spec
    function _initializeCategories() internal {
        categories[STAKING_REWARDS] = Category({
            totalAllocation: 45_000_000 * 1e18,
            allocated: 0,
            tgeUnlockBps: 0,
            cliffDuration: 0,
            vestingDuration: 60 * 30 days
        });

        categories[ECOSYSTEM] = Category({
            totalAllocation: 37_500_000 * 1e18,
            allocated: 0,
            tgeUnlockBps: 500,
            cliffDuration: 6 * 30 days,
            vestingDuration: 36 * 30 days
        });

        categories[LIQUIDITY] = Category({
            totalAllocation: 25_000_000 * 1e18,
            allocated: 0,
            tgeUnlockBps: 10000,
            cliffDuration: 0,
            vestingDuration: 0
        });

        categories[MARKETING] = Category({
            totalAllocation: 25_000_000 * 1e18,
            allocated: 0,
            tgeUnlockBps: 1000,
            cliffDuration: 3 * 30 days,
            vestingDuration: 24 * 30 days
        });

        categories[TEAM] = Category({
            totalAllocation: 17_500_000 * 1e18,
            allocated: 0,
            tgeUnlockBps: 0,
            cliffDuration: 12 * 30 days,
            vestingDuration: 36 * 30 days
        });

        categories[ADVISORS] = Category({
            totalAllocation: 10_000_000 * 1e18,
            allocated: 0,
            tgeUnlockBps: 0,
            cliffDuration: 9 * 30 days,
            vestingDuration: 24 * 30 days
        });

        categories[AIRDROP] = Category({
            totalAllocation: 10_000_000 * 1e18,
            allocated: 0,
            tgeUnlockBps: 5000,
            cliffDuration: 0,
            vestingDuration: 12 * 30 days
        });

        categories[RESERVE] = Category({
            totalAllocation: 5_000_000 * 1e18,
            allocated: 0,
            tgeUnlockBps: 0,
            cliffDuration: 12 * 30 days,
            vestingDuration: 48 * 30 days
        });
    }
}
