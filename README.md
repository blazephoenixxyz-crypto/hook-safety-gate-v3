# HookSafetyGate v3

A standalone, default-closed admission gate for Uniswap v4 hook routing.
Zero external dependencies. One line of integration.

## What it does

**Layer 1 — Delta-permission screen**
Rejects hooks with BEFORE_SWAP_RETURNS_DELTA_FLAG or AFTER_SWAP_RETURNS_DELTA_FLAG via address bitmask. Pure arithmetic, unfakeable, constant time.

**Layer 2 — Default-closed allowlist**
Nothing is routable unless explicitly admitted by the owner.

**Layer 3 — Codehash pinning**
On admission, the hook's EXTCODEHASH is recorded. If the code changes after admission (proxy upgrade, selfdestruct-redeploy), the hook is automatically blocked automatically.

## v3: Delta hook timelock path

Non-delta hooks are admitted immediately via allowHook().

Delta hooks (custom accounting) require a two-step, time-locked process:

1. proposeDeltaHook(hook) — records the codehash and starts the public review window
2. confirmDeltaHook(hook) — callable only after deltaAdmissionDelay seconds

Bait-and-switch defense: if the hook's code changes between propose and confirm, confirmation reverts.

isRoutableDeltaHook(hook) lets integrators identify and handle delta hooks separately.

## Integration

One line in any v4 router or aggregator:

    if (!IHookSafetyGate(GATE).isRoutableHook(address(key.hooks))) revert UnsafeHook();

Works on any EVM chain with Uniswap v4. Zero external dependencies.

## Tests

38 tests, 768 fuzz runs, 0 failures.

## Related

- hook-safety-gate: v1 (Layer 1 + 2)
- hook-safety-gate-v2: v2 (Layer 1 + 2 + 3)

## License

MIT
