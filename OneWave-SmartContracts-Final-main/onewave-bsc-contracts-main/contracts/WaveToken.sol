// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {ERC20Pausable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title WaveToken — Core token of the OneWave ecosystem
/// @author OneWave
/// @notice Fixed-supply ERC-20 (250 million WAVE) with burn, pause, permit, and migration-only mint
/// @dev Total supply is hard-capped at MAX_SUPPLY. Migration minting can only restore burned tokens
///      up to the cap — it cannot inflate beyond 250M. Inherits ERC20Permit for gasless approvals (EIP-2612).
contract WaveToken is ERC20, ERC20Burnable, ERC20Pausable, ERC20Permit, AccessControl {

    /// @dev Thrown when minting would push totalSupply above MAX_SUPPLY
    error WaveToken__ExceedsMaxSupply(uint256 requested, uint256 available);

    /// @dev Thrown when a zero address is passed where a valid recipient is required
    error WaveToken__ZeroAddress();

    /// @notice Emitted when migration tokens are minted
    /// @param to Recipient of the minted tokens
    /// @param amount Number of tokens minted (in wei)
    event MigrationMinted(address indexed to, uint256 amount);

    uint256 public constant MAX_SUPPLY = 250_000_000 * 1e18; // 250M WAVE (18 decimals)
    bytes32 public constant MIGRATION_ROLE = keccak256("MIGRATION_ROLE"); // cross-chain migration only

    /// @notice Deploys WaveToken, mints full MAX_SUPPLY to deployer, and assigns admin role
    /// @dev MIGRATION_ROLE is not granted at deploy — must be explicitly granted for migration use
    constructor() ERC20("OneWave", "WAVE") ERC20Permit("OneWave") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _mint(msg.sender, MAX_SUPPLY);
    }

    /// @notice Mint tokens — restricted to MIGRATION_ROLE only
    /// @dev Reverts if minting would exceed MAX_SUPPLY or if `to` is the zero address.
    ///      This function exists solely for cross-chain migration scenarios where burned
    ///      tokens need to be re-minted on this chain.
    /// @param to Address to receive the minted tokens
    /// @param amount Number of tokens to mint (in wei)
    function mint(address to, uint256 amount) external onlyRole(MIGRATION_ROLE) {
        if (to == address(0)) revert WaveToken__ZeroAddress();
        uint256 available = MAX_SUPPLY - totalSupply();
        if (amount > available) revert WaveToken__ExceedsMaxSupply(amount, available);
        _mint(to, amount);
        emit MigrationMinted(to, amount);
    }

    /// @notice Pause all token transfers — admin only
    /// @dev Also blocks minting and burning while paused
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause token transfers — admin only
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Check if this contract supports a given interface
    /// @param interfaceId The interface identifier (ERC-165)
    /// @return True if the interface is supported
    function supportsInterface(bytes4 interfaceId) public view override(AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    /// @dev Required override: ERC20Pausable hooks into _update to block transfers while paused
    function _update(address from, address to, uint256 value) internal override(ERC20, ERC20Pausable) {
        super._update(from, to, value);
    }
}
