// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title Governance — On-chain governance for the OneWave ecosystem
/// @author OneWave
/// @notice Allows WAVE token holders to create proposals, vote, and execute protocol decisions.
///         Voters must lock their WAVE tokens for the voting period to prevent flash-loan manipulation.
///         Proposers must lock proposalThreshold tokens to prevent flash-loan proposal spam.
/// @dev Proposal lifecycle: Active → Succeeded/Defeated → Queued → Executed (or Cancelled).
///      Timelock delay between queue and execution provides safety.
///      Queued proposals expire after GRACE_PERIOD.
///      Vote locking prevents flash-loan attacks and double-voting with transferred tokens.
///      Proposer deposit locking prevents flash-loan proposal creation.
///      Explicit finalization transitions proposals to Succeeded/Defeated.
contract Governance is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /// @dev Thrown when a zero address is provided
    error Governance__ZeroAddress();

    /// @dev Thrown when a zero amount or duration is provided
    error Governance__ZeroValue();

    /// @dev Thrown when the proposer doesn't hold enough WAVE to create a proposal
    error Governance__BelowProposalThreshold(uint256 balance, uint256 threshold);

    /// @dev Thrown when referencing a proposal that doesn't exist
    error Governance__InvalidProposalId(uint256 proposalId);

    /// @dev Thrown when the proposal is not in the required state for the action
    error Governance__InvalidState(uint256 proposalId, ProposalState current, ProposalState required);

    /// @dev Thrown when a user tries to vote on a proposal they already voted on
    error Governance__AlreadyVoted(uint256 proposalId, address voter);

    /// @dev Thrown when trying to execute a proposal before the timelock expires
    error Governance__TimelockNotExpired(uint256 proposalId, uint256 executeAfter);

    /// @dev Thrown when a proposal did not reach quorum
    error Governance__QuorumNotReached(uint256 proposalId, uint256 totalVotes, uint256 quorum);

    /// @dev Thrown when a proposal did not pass (more against than for)
    error Governance__ProposalDefeated(uint256 proposalId);

    /// @dev Thrown when trying to execute an expired queued proposal
    error Governance__ProposalExpired(uint256 proposalId);

    /// @dev Thrown when a non-admin non-proposer tries to cancel a proposal
    error Governance__Unauthorized();

    /// @dev Thrown when trying to withdraw locked votes before voting ends
    error Governance__VotesStillLocked(uint256 proposalId, uint256 endTime);

    /// @dev Thrown when trying to finalize a proposal whose voting period hasn't ended
    error Governance__VotingNotEnded(uint256 proposalId, uint256 endTime);

    /// @notice Emitted when a new proposal is created
    event ProposalCreated(uint256 indexed proposalId, address indexed proposer, string description);

    /// @notice Emitted when a vote is cast (tokens locked)
    event VoteCast(uint256 indexed proposalId, address indexed voter, bool support, uint256 weight);

    /// @notice Emitted when a proposal is finalized to Succeeded or Defeated
    event ProposalFinalized(uint256 indexed proposalId, ProposalState state);

    /// @notice Emitted when a proposal is queued for execution
    event ProposalQueued(uint256 indexed proposalId, uint256 executeAfter);

    /// @notice Emitted when a proposal is executed
    event ProposalExecuted(uint256 indexed proposalId);

    /// @notice Emitted when a proposal is cancelled
    event ProposalCancelled(uint256 indexed proposalId);

    /// @notice Emitted when a proposer's deposit is forfeited due to proposer-initiated cancellation
    event ProposerDepositForfeited(uint256 indexed proposalId, address indexed proposer, uint256 amount);

    /// @notice Emitted when governance parameters are updated
    event ParametersUpdated(uint256 votingPeriod, uint256 quorum, uint256 proposalThreshold, uint256 timelockDelay);

    /// @notice Emitted when a voter withdraws their locked tokens after voting ends
    event VotesWithdrawn(uint256 indexed proposalId, address indexed voter, uint256 amount);

    /// @notice Emitted when a proposer withdraws their locked deposit
    event ProposerDepositWithdrawn(uint256 indexed proposalId, address indexed proposer, uint256 amount);

    enum ProposalState {
        Active,
        Succeeded,
        Defeated,
        Queued,
        Executed,
        Cancelled
    }

    struct Proposal {
        address proposer;
        string description;
        uint256 startTime;
        uint256 endTime;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 executeAfter;
        uint256 quorumSnapshot;      // quorum at creation time
        uint256 proposerDeposit;     // locked tokens from proposer
        ProposalState state;
        mapping(address => bool) hasVoted;
        mapping(address => uint256) lockedAmount; // tokens locked by each voter
    }

    /// @dev Grace period: queued proposals expire 14 days after executeAfter
    uint256 public constant GRACE_PERIOD = 14 days;

    IERC20 public immutable waveToken;

    uint256 public votingPeriod;
    uint256 public quorum;
    uint256 public proposalThreshold;
    uint256 public timelockDelay;

    uint256 public proposalCount;
    mapping(uint256 => Proposal) internal _proposals;

    /// @notice Deploys Governance with the WAVE token and default parameters
    /// @param _waveToken Address of the WAVE ERC-20 token
    /// @param _votingPeriod Voting window duration in seconds
    /// @param _quorum Minimum total votes for a valid proposal (in wei)
    /// @param _proposalThreshold Minimum WAVE balance to create proposals (in wei)
    /// @param _timelockDelay Seconds between queue and execution
    constructor(
        address _waveToken,
        uint256 _votingPeriod,
        uint256 _quorum,
        uint256 _proposalThreshold,
        uint256 _timelockDelay
    ) {
        if (_waveToken == address(0)) revert Governance__ZeroAddress();
        if (_votingPeriod == 0 || _quorum == 0 || _proposalThreshold == 0 || _timelockDelay == 0) {
            revert Governance__ZeroValue();
        }
        waveToken = IERC20(_waveToken);
        votingPeriod = _votingPeriod;
        quorum = _quorum;
        proposalThreshold = _proposalThreshold;
        timelockDelay = _timelockDelay;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /// @notice Create a new governance proposal
    /// @dev Proposer must hold and lock proposalThreshold WAVE. Snapshots quorum at creation.
    ///      Tokens are locked to prevent flash-loan proposal spam.
    /// @param description Text description of the proposal
    /// @return proposalId The ID of the newly created proposal
    function createProposal(string calldata description) external nonReentrant whenNotPaused returns (uint256 proposalId) {
        uint256 balance = waveToken.balanceOf(msg.sender);
        if (balance < proposalThreshold) revert Governance__BelowProposalThreshold(balance, proposalThreshold);

        // Lock proposalThreshold tokens to prevent flash-loan proposal spam
        waveToken.safeTransferFrom(msg.sender, address(this), proposalThreshold);

        proposalId = ++proposalCount;
        Proposal storage p = _proposals[proposalId];
        p.proposer = msg.sender;
        p.description = description;
        p.startTime = block.timestamp;
        p.endTime = block.timestamp + votingPeriod;
        p.state = ProposalState.Active;
        p.quorumSnapshot = quorum;
        p.proposerDeposit = proposalThreshold;

        emit ProposalCreated(proposalId, msg.sender, description);
    }

    /// @notice Cast a vote on an active proposal — tokens are LOCKED in the contract until voting ends
    /// @dev Voters transfer WAVE to this contract. This prevents flash-loan attacks and double-voting
    ///      with transferred tokens. Tokens can be withdrawn after p.endTime via withdrawVotes().
    /// @param proposalId ID of the proposal to vote on
    /// @param support True for yes, false for no
    /// @param amount Amount of WAVE tokens to vote with (locked for voting period)
    function vote(uint256 proposalId, bool support, uint256 amount) external nonReentrant whenNotPaused {
        Proposal storage p = _proposals[proposalId];
        if (p.proposer == address(0)) revert Governance__InvalidProposalId(proposalId);
        if (p.state != ProposalState.Active) {
            revert Governance__InvalidState(proposalId, p.state, ProposalState.Active);
        }
        if (block.timestamp > p.endTime) {
            revert Governance__VotingNotEnded(proposalId, p.endTime);
        }
        if (p.hasVoted[msg.sender]) revert Governance__AlreadyVoted(proposalId, msg.sender);
        if (amount == 0) revert Governance__ZeroValue();

        // Lock tokens in this contract — prevents flash loans and double-voting
        waveToken.safeTransferFrom(msg.sender, address(this), amount);

        p.hasVoted[msg.sender] = true;
        p.lockedAmount[msg.sender] = amount;

        if (support) {
            p.forVotes += amount;
        } else {
            p.againstVotes += amount;
        }

        emit VoteCast(proposalId, msg.sender, support, amount);
    }

    /// @notice Withdraw locked voting tokens after the voting period ends or proposal is cancelled
    /// @param proposalId ID of the proposal to withdraw votes from
    function withdrawVotes(uint256 proposalId) external nonReentrant {
        Proposal storage p = _proposals[proposalId];
        if (p.proposer == address(0)) revert Governance__InvalidProposalId(proposalId);
        if (p.state != ProposalState.Cancelled && block.timestamp <= p.endTime) {
            revert Governance__VotesStillLocked(proposalId, p.endTime);
        }

        uint256 locked = p.lockedAmount[msg.sender];
        if (locked == 0) revert Governance__ZeroValue();

        p.lockedAmount[msg.sender] = 0;
        waveToken.safeTransfer(msg.sender, locked);

        emit VotesWithdrawn(proposalId, msg.sender, locked);
    }

    /// @notice Withdraw proposer's locked deposit after voting ends or proposal is cancelled
    /// @param proposalId ID of the proposal to withdraw deposit from
    function withdrawProposerDeposit(uint256 proposalId) external nonReentrant {
        Proposal storage p = _proposals[proposalId];
        if (msg.sender != p.proposer) revert Governance__Unauthorized();
        // Can withdraw after voting ends or if proposal was cancelled
        if (p.state != ProposalState.Cancelled && block.timestamp <= p.endTime) {
            revert Governance__VotesStillLocked(proposalId, p.endTime);
        }

        uint256 deposit = p.proposerDeposit;
        if (deposit == 0) revert Governance__ZeroValue();

        p.proposerDeposit = 0;
        waveToken.safeTransfer(msg.sender, deposit);

        emit ProposerDepositWithdrawn(proposalId, msg.sender, deposit);
    }

    /// @notice Finalize a proposal after voting ends — transitions to Succeeded or Defeated
    /// @dev Can be called by anyone after voting period ends. Also called automatically by queueProposal.
    /// @param proposalId ID of the proposal to finalize
    function finalizeProposal(uint256 proposalId) public whenNotPaused {
        Proposal storage p = _proposals[proposalId];
        if (p.proposer == address(0)) revert Governance__InvalidProposalId(proposalId);
        if (p.state != ProposalState.Active) {
            revert Governance__InvalidState(proposalId, p.state, ProposalState.Active);
        }
        if (block.timestamp <= p.endTime) {
            revert Governance__VotingNotEnded(proposalId, p.endTime);
        }

        uint256 totalVotes = p.forVotes + p.againstVotes;
        if (totalVotes >= p.quorumSnapshot && p.forVotes > p.againstVotes) {
            p.state = ProposalState.Succeeded;
        } else {
            p.state = ProposalState.Defeated;
        }

        emit ProposalFinalized(proposalId, p.state);
    }

    /// @notice Queue a succeeded proposal for execution after timelock
    /// @dev Auto-finalizes the proposal if still in Active state
    /// @param proposalId ID of the proposal to queue
    function queueProposal(uint256 proposalId) external whenNotPaused {
        Proposal storage p = _proposals[proposalId];
        if (p.proposer == address(0)) revert Governance__InvalidProposalId(proposalId);

        // Auto-finalize if still Active
        if (p.state == ProposalState.Active) {
            finalizeProposal(proposalId);
        }

        if (p.state != ProposalState.Succeeded) {
            revert Governance__InvalidState(proposalId, p.state, ProposalState.Succeeded);
        }

        p.state = ProposalState.Queued;
        p.executeAfter = block.timestamp + timelockDelay;

        emit ProposalQueued(proposalId, p.executeAfter);
    }

    /// @notice Execute a queued proposal after the timelock delay
    /// @dev Reverts if proposal has expired (past GRACE_PERIOD after executeAfter)
    /// @param proposalId ID of the proposal to execute
    function executeProposal(uint256 proposalId) external whenNotPaused {
        Proposal storage p = _proposals[proposalId];
        if (p.proposer == address(0)) revert Governance__InvalidProposalId(proposalId);
        if (p.state != ProposalState.Queued) {
            revert Governance__InvalidState(proposalId, p.state, ProposalState.Queued);
        }
        if (block.timestamp < p.executeAfter) {
            revert Governance__TimelockNotExpired(proposalId, p.executeAfter);
        }
        // Queued proposals expire after GRACE_PERIOD
        if (block.timestamp > p.executeAfter + GRACE_PERIOD) {
            revert Governance__ProposalExpired(proposalId);
        }

        p.state = ProposalState.Executed;
        emit ProposalExecuted(proposalId);
    }

    /// @notice Cancel a proposal — only admin or the original proposer
    /// @param proposalId ID of the proposal to cancel
    function cancelProposal(uint256 proposalId) external {
        Proposal storage p = _proposals[proposalId];
        if (p.proposer == address(0)) revert Governance__InvalidProposalId(proposalId);
        if (p.state == ProposalState.Executed || p.state == ProposalState.Cancelled) {
            revert Governance__InvalidState(proposalId, p.state, ProposalState.Active);
        }

        bool isAdmin = hasRole(DEFAULT_ADMIN_ROLE, msg.sender);
        bool isProposer = msg.sender == p.proposer;
        if (!isAdmin && !isProposer) {
            revert Governance__Unauthorized();
        }

        p.state = ProposalState.Cancelled;

        if (isProposer && !isAdmin) {
            uint256 forfeited = p.proposerDeposit;
            p.proposerDeposit = 0;
            emit ProposerDepositForfeited(proposalId, msg.sender, forfeited);
        }

        emit ProposalCancelled(proposalId);
    }

    /// @notice Get proposal details
    /// @param proposalId ID of the proposal
    /// @return proposer Address of the proposer
    /// @return description Proposal description text
    /// @return startTime Voting start timestamp
    /// @return endTime Voting end timestamp
    /// @return forVotes Total votes in favor (in wei)
    /// @return againstVotes Total votes against (in wei)
    /// @return state Current proposal state
    function getProposal(uint256 proposalId) external view returns (
        address proposer,
        string memory description,
        uint256 startTime,
        uint256 endTime,
        uint256 forVotes,
        uint256 againstVotes,
        ProposalState state
    ) {
        Proposal storage p = _proposals[proposalId];
        if (p.proposer == address(0)) revert Governance__InvalidProposalId(proposalId);
        return (p.proposer, p.description, p.startTime, p.endTime, p.forVotes, p.againstVotes, p.state);
    }

    /// @notice Get a user's voting power (current WAVE balance)
    /// @param user Address to query
    /// @return Current WAVE balance (in wei)
    function getVotingPower(address user) external view returns (uint256) {
        return waveToken.balanceOf(user);
    }

    /// @notice Get the amount of tokens a voter has locked in a proposal
    /// @param proposalId ID of the proposal
    /// @param voter Address of the voter
    /// @return Locked WAVE tokens (in wei)
    function getLockedVotes(uint256 proposalId, address voter) external view returns (uint256) {
        return _proposals[proposalId].lockedAmount[voter];
    }

    /// @notice Get the proposer's locked deposit for a proposal
    /// @param proposalId ID of the proposal
    /// @return Locked deposit amount (in wei)
    function getProposerDeposit(uint256 proposalId) external view returns (uint256) {
        return _proposals[proposalId].proposerDeposit;
    }

    /// @notice Update governance parameters — admin only
    /// @param _votingPeriod Voting window duration in seconds
    /// @param _quorum Minimum total votes for a valid proposal (in wei)
    /// @param _proposalThreshold Minimum WAVE balance to create proposals (in wei)
    /// @param _timelockDelay Seconds between queue and execution
    function setParameters(
        uint256 _votingPeriod,
        uint256 _quorum,
        uint256 _proposalThreshold,
        uint256 _timelockDelay
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_votingPeriod == 0 || _quorum == 0 || _proposalThreshold == 0 || _timelockDelay == 0) {
            revert Governance__ZeroValue();
        }
        votingPeriod = _votingPeriod;
        quorum = _quorum;
        proposalThreshold = _proposalThreshold;
        timelockDelay = _timelockDelay;
        emit ParametersUpdated(_votingPeriod, _quorum, _proposalThreshold, _timelockDelay);
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
