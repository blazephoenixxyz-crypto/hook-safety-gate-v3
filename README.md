# HookSafetyGate v3

A standalone, default-closed admission gate for the **routing side** of Uniswap v4 hook safety.
Zero external dependencies. One line of integration. MIT.

`HookSafetyGate` lets any v4 integrator — a router, an aggregator, a periphery contract, or an
off-chain solver — decide whether a pool's hook is safe to route through **before any token
moves**. It holds no funds, makes no external calls into the hook, and cannot move tokens: it is
a predicate plus an owner-managed admission book.

> **Three gates, three policies — pick the one that matches your risk appetite.** These are not
> superseded versions; v3 is the most permissive of the three, not a strict superset.
>
> | | Codehash pinning | Delta-returning hooks |
> |---|---|---|
> | [v1](https://github.com/blazephoenixxyz-crypto/hook-safety-gate) | no | never routable |
> | [v2](https://github.com/blazephoenixxyz-crypto/hook-safety-gate-v2) | yes | never routable |
> | **v3** (this repo) | yes | admissible via a two-step timelock |
>
> If you want delta-returning hooks refused outright, **v2 is the gate you want** — v3
> deliberately gives that guarantee up in exchange for a governed path to admitting them.

## Why this exists

v4 hooks are arbitrary third-party code in the swap path. The existing protections — the
PoolManager's own flag enforcement, end-state slippage bounds, and off-chain interface
allowlists — are each necessary, but they leave the routing layer without a deterministic,
on-chain, default-closed gate. Losses have already occurred at the hook/router layer rather
than in the AMM maths itself.

The gap this closes is narrow and specific: **an allowlist keyed on an address admits an
address, not the code at it.** A hook reviewed as benign and later pointed at a different
implementation keeps passing an address check, and the review that preceded admission then
applies to a program that is no longer the one executing.

## The three layers

**Layer 1 — delta-permission screen (immutable, pure).**
A hook's permissions are encoded in its own address, so the screen is arithmetic on a bitmask:
constant time, no external call, and nothing the hook can misreport. `BEFORE_SWAP_RETURNS_DELTA`
and `AFTER_SWAP_RETURNS_DELTA` are the two flags that let a hook modify swap accounting, so they
are the two that change the trust decision. Flag values are redeclared verbatim from
`Uniswap/v4-core` `Hooks.sol` and pinned by a test, so the contract audits and deploys in
isolation.

**Layer 2 — default-closed allowlist (governed).**
Nothing is routable unless explicitly admitted. Anything unknown is denied. This covers
griefing, gas exhaustion, and behaviour the flags do not describe.

**Layer 3 — codehash pinning.**
`EXTCODEHASH` is recorded at admission and re-checked at routing time. If the code changes after
admission — proxy upgrade, redeploy — the hook stops being routable instead of silently
continuing to be routed through.

## The delta path: two-step, timelocked

v1 and v2 refused delta-returning hooks outright. v3 admits them, but only through a process
that makes the admission observable before it takes effect:

1. `proposeDeltaHook(hook)` — records the codehash and opens a public review window.
2. `confirmDeltaHook(hook)` — callable only after `deltaAdmissionDelay` seconds.

Confirmation reverts if the hook's code changed between proposal and confirmation, which closes
the bait-and-switch of proposing benign code and confirming something else. Non-delta hooks are
still admitted directly via `allowHook()`. `isRoutableDeltaHook(hook)` lets an integrator
identify delta hooks and handle them under a separate policy.

## Integration

One line in any v4 router or aggregator:

```solidity
if (!IHookSafetyGate(GATE).isRoutableHook(address(key.hooks))) revert UnsafeHook();
```

Works on any EVM chain with Uniswap v4.

## Invariants (all covered by the test suite)

- Unknown hooks return `false` — default-closed.
- `address(0)` (hookless pools) is always routable.
- An admitted hook whose `EXTCODEHASH` no longer matches the pinned value is not routable.
- A delta-returning hook is routable only after propose → delay → confirm, and confirmation
  reverts if its code changed during the window.
- Only the owner can admit, propose or confirm.
- The contract holds no funds, moves no tokens, and never calls into the hook.

## What this is not

Admission is an **owner decision**. This is a tool for an integrator to express its own risk
policy — not a protocol-level or trustless mechanism, and not something that belongs anywhere
near core. The router is the party choosing to route, so the router is the party that carries
the policy; but the design is only as good as the admitting party, and it is worth saying that
plainly rather than letting the phrase "safety gate" imply more than it delivers.

## Build & test

```bash
forge install foundry-rs/forge-std
forge build
forge test -vvv
```

38 tests, 768 fuzz runs, 0 failures.

## License

MIT. The technique is published as a public good; no exclusivity is claimed.

## Author

Mitra — [BlazePhoenix](https://blazephoenix.xyz)
