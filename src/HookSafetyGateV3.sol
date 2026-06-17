// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  HookSafetyGateV3
/// @notice A standalone, default-closed admission gate that lets any Uniswap v4
///         integrator decide whether a pool's hook is safe to route through,
///         BEFORE any token moves. v3 keeps every guarantee of v2 and adds an
///         explicit, deliberately-harder path for admitting hooks that DO carry
///         return-delta permissions (custom-accounting hooks), so an integrator
///         is no longer forced to choose between "block all delta hooks" and
///         "route them blind".
///
///         WHAT v3 CHANGES (and, just as importantly, what it does NOT):
///
///           - v2 treated any delta-flagged hook as permanently non-routable.
///             v3 lets the owner admit a specific delta hook through a two-step,
///             time-locked path (propose -> wait -> confirm). This mirrors what a
///             routing operator already does off-chain today (review, then
///             allow-list), but makes it on-chain, auditable and immutable.
///
///           - Admitting a delta hook DOES NOT make it safe. A delta hook, by the
///             PoolManager's own design, retains the structural ability to alter
///             swap accounting. The gate cannot and does not certify the hook's
///             runtime behaviour. The codehash pin guarantees the *code* the owner
///             reviewed is the code that runs - it does NOT guarantee that code is
///             benign on all paths. For delta hooks, v3 therefore reduces to the
///             same trust model Uniswap already uses (human review + admission),
///             only enforced on-chain. The timelock exists precisely because this
///             admission carries real risk and deserves a public review window.
///
///         THREE LAYERS (unchanged in spirit from v2):
///           Layer 1 - Delta-permission screen. A hook with NO delta flags can be
///             admitted on the standard, immediate path. A hook WITH delta flags
///             can only ever be routable via the explicit delta path below.
///           Layer 2 - Default-closed allow-list. Nothing is routable unless the
///             owner admitted it.
///           Layer 3 - Code-hash pinning. Routability requires the hook's current
///             EXTCODEHASH to equal the hash pinned at admission. Applies to BOTH
///             non-delta and delta admissions. Any code change (proxy upgrade,
///             selfdestruct-redeploy) auto-revokes routability until re-review.
///
///         The contract holds no funds, makes no external calls into hook code,
///         and cannot move tokens. Integrators call `isRoutableHook(hook)` and act
///         on the boolean.
///
/// @dev    Permission-flag values are taken verbatim from the canonical Uniswap v4
///         `Hooks` library (Uniswap/v4-core, src/libraries/Hooks.sol) and verified
///         against it in the test suite. Zero external dependencies by design.
///
///           BEFORE_SWAP_RETURNS_DELTA_FLAG = 1 << 3  (0x08)
///           AFTER_SWAP_RETURNS_DELTA_FLAG  = 1 << 2  (0x04)
contract HookSafetyGateV3 {
    // -------------------------------------------------------------------------
    // Constants - verbatim from Uniswap v4-core Hooks.sol, verified in tests.
    // -------------------------------------------------------------------------

    uint160 internal constant BEFORE_SWAP_RETURNS_DELTA_FLAG = uint160(1 << 3);
    uint160 internal constant AFTER_SWAP_RETURNS_DELTA_FLAG = uint160(1 << 2);

    /// @notice Mask of all accounting-altering permission bits.
    uint160 internal constant DELTA_FLAGS_MASK =
        BEFORE_SWAP_RETURNS_DELTA_FLAG | AFTER_SWAP_RETURNS_DELTA_FLAG;

    /// @notice Minimum delay between proposing and confirming a delta-hook
    ///         admission. Gives the public a fixed window to inspect the proposed
    ///         hook before it can become routable. Immutable; set at deploy.
    uint256 public immutable deltaAdmissionDelay;

    // -------------------------------------------------------------------------
    // Types
    // -------------------------------------------------------------------------

    /// @dev Admission state for a hook address.
    ///        None    - never admitted (default).
    ///        Clean   - admitted via the standard path; carries no delta flags.
    ///        Delta   - admitted via the time-locked delta path; carries delta flags.
    enum Status {
        None,
        Clean,
        Delta
    }

    /// @dev A pending delta admission awaiting confirmation.
    struct PendingDelta {
        bytes32 codeHash; // code hash captured at propose time
        uint64 eta; // earliest timestamp at which confirm is allowed
    }

    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------

    /// @notice The address permitted to manage admissions.
    address public owner;

    /// @notice Admission status per hook.
    mapping(address hook => Status status) public statusOf;

    /// @notice Code hash pinned at admission time (for Clean and Delta alike).
    ///         Routability requires the hook's current code hash to equal this.
    mapping(address hook => bytes32 pinnedCodeHash) public pinnedCodeHash;

    /// @notice Pending (proposed, not yet confirmed) delta admissions.
    mapping(address hook => PendingDelta pending) public pendingDelta;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    event OwnerTransferred(address indexed previousOwner, address indexed newOwner);
    event HookAllowed(address indexed hook, bytes32 codeHash);
    event HookDenied(address indexed hook);

    event DeltaHookProposed(address indexed hook, bytes32 codeHash, uint64 eta);
    event DeltaHookConfirmed(address indexed hook, bytes32 codeHash);
    event DeltaHookProposalCancelled(address indexed hook);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error NotOwner();
    error HookHasDeltaFlags(address hook);
    error HookLacksDeltaFlags(address hook);
    error ZeroAddress();
    error HookHasNoCode(address hook);
    error NoPendingProposal(address hook);
    error ProposalNotReady(address hook, uint64 eta);
    error CodeHashChangedSinceProposal(address hook);

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /// @param initialOwner   address allowed to manage admissions
    /// @param admissionDelay seconds that must elapse between proposing and
    ///                        confirming a delta-hook admission (public review window)
    constructor(address initialOwner, uint256 admissionDelay) {
        if (initialOwner == address(0)) revert ZeroAddress();
        owner = initialOwner;
        deltaAdmissionDelay = admissionDelay;
        emit OwnerTransferred(address(0), initialOwner);
    }

    // -------------------------------------------------------------------------
    // Layer 1 - pure delta-permission screen
    // -------------------------------------------------------------------------

    /// @notice Returns true iff the hook address carries NO return-delta flag.
    /// @dev    Pure. Reads only the address. Never calls the hook. Constant time.
    function hasNoDeltaFlags(address hook) public pure returns (bool) {
        return (uint160(hook) & DELTA_FLAGS_MASK) == 0;
    }

    // -------------------------------------------------------------------------
    // Combined predicate - the function integrators call
    // -------------------------------------------------------------------------

    /// @notice The single predicate an integrator consults before routing a v4 leg.
    ///         Returns true iff EITHER:
    ///           (a) the pool has no hook (`hook == address(0)`), OR
    ///           (b) the hook is admitted (Clean or Delta) AND its current code
    ///               hash still equals the hash pinned at admission.
    /// @dev    View. One status SLOAD, one pin SLOAD, one EXTCODEHASH. The Layer-1
    ///         screen is enforced at admission time (a Clean hook can never carry
    ///         delta flags; a Delta status is only reachable via the timelocked
    ///         path), so routability need only check admission + pin here.
    function isRoutableHook(address hook) external view returns (bool) {
        if (hook == address(0)) return true;
        Status s = statusOf[hook];
        if (s == Status.None) return false; // default-closed
        return hook.codehash == pinnedCodeHash[hook]; // Layer 3 - code unchanged
    }

    /// @notice True iff the hook is admitted but its code has since changed.
    function isStale(address hook) external view returns (bool) {
        if (statusOf[hook] == Status.None) return false;
        return hook.codehash != pinnedCodeHash[hook];
    }

    /// @notice True iff the hook is a routable delta (custom-accounting) hook.
    ///         Integrators that wish to warn users, or apply extra slippage
    ///         protection, can branch on this without a second call.
    function isRoutableDeltaHook(address hook) external view returns (bool) {
        if (statusOf[hook] != Status.Delta) return false;
        return hook.codehash == pinnedCodeHash[hook];
    }

    // -------------------------------------------------------------------------
    // Standard admission (non-delta hooks) - immediate, owner only
    // -------------------------------------------------------------------------

    /// @notice Admit a NON-delta hook and pin its current code hash. Immediate.
    /// @dev    Reverts if the hook carries any delta flag (use the delta path),
    ///         is the zero address, or has no code. Re-admitting re-pins.
    function allowHook(address hook) external onlyOwner {
        if (hook == address(0)) revert ZeroAddress();
        if (!hasNoDeltaFlags(hook)) revert HookHasDeltaFlags(hook);
        bytes32 h = hook.codehash;
        if (h == bytes32(0) || h == keccak256("")) revert HookHasNoCode(hook);
        statusOf[hook] = Status.Clean;
        pinnedCodeHash[hook] = h;
        emit HookAllowed(hook, h);
    }

    // -------------------------------------------------------------------------
    // Delta admission - two-step, time-locked, owner only
    // -------------------------------------------------------------------------

    /// @notice Step 1: propose admitting a DELTA hook. Records the current code
    ///         hash and starts the public review window. Does NOT make the hook
    ///         routable. Re-proposing overwrites the prior proposal.
    /// @dev    Reverts if the hook carries NO delta flag (use the standard path),
    ///         is the zero address, or has no code.
    function proposeDeltaHook(address hook) external onlyOwner {
        if (hook == address(0)) revert ZeroAddress();
        if (hasNoDeltaFlags(hook)) revert HookLacksDeltaFlags(hook);
        bytes32 h = hook.codehash;
        if (h == bytes32(0) || h == keccak256("")) revert HookHasNoCode(hook);

        uint64 eta = uint64(block.timestamp + deltaAdmissionDelay);
        pendingDelta[hook] = PendingDelta({codeHash: h, eta: eta});
        emit DeltaHookProposed(hook, h, eta);
    }

    /// @notice Step 2: confirm a previously proposed delta hook after the delay.
    ///         Admits the hook (Status.Delta) and pins its code hash.
    /// @dev    Reverts if there is no pending proposal, the delay has not elapsed,
    ///         or the hook's code hash changed since the proposal (preventing a
    ///         bait-and-switch between propose and confirm).
    function confirmDeltaHook(address hook) external onlyOwner {
        PendingDelta memory p = pendingDelta[hook];
        if (p.eta == 0) revert NoPendingProposal(hook);
        if (block.timestamp < p.eta) revert ProposalNotReady(hook, p.eta);
        if (hook.codehash != p.codeHash) revert CodeHashChangedSinceProposal(hook);

        statusOf[hook] = Status.Delta;
        pinnedCodeHash[hook] = p.codeHash;
        delete pendingDelta[hook];
        emit DeltaHookConfirmed(hook, p.codeHash);
    }

    /// @notice Cancel a pending delta proposal before confirmation. Idempotent.
    function cancelDeltaProposal(address hook) external onlyOwner {
        if (pendingDelta[hook].eta != 0) {
            delete pendingDelta[hook];
            emit DeltaHookProposalCancelled(hook);
        }
    }

    // -------------------------------------------------------------------------
    // Revocation (both kinds) - owner only
    // -------------------------------------------------------------------------

    /// @notice Remove a hook from the allow-list (Clean or Delta). Clears its pin
    ///         and any pending delta proposal. Idempotent.
    function denyHook(address hook) external onlyOwner {
        bool changed;
        if (statusOf[hook] != Status.None) {
            statusOf[hook] = Status.None;
            pinnedCodeHash[hook] = bytes32(0);
            changed = true;
        }
        if (pendingDelta[hook].eta != 0) {
            delete pendingDelta[hook];
            changed = true;
        }
        if (changed) emit HookDenied(hook);
    }

    // -------------------------------------------------------------------------
    // Ownership
    // -------------------------------------------------------------------------

    /// @notice Transfer admission ownership (e.g. deploy key -> multisig / DAO).
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnerTransferred(owner, newOwner);
        owner = newOwner;
    }
}
