# Atomic Bundles

Smart contracts for CoW Protocol atomic bundles (formerly Generalized Wrappers).

For a full explanation of atomic bundles — what they are, when to use them, security requirements, and gas costs — see the [CoW Protocol documentation](https://docs.cow.fi/cow-protocol/reference/contracts/periphery/wrapper).

## Contracts

| Contract | Description |
|---|---|
| `CowWrapper.sol` | Abstract base contract and interfaces (`ICowWrapper`, `ICowSettlement`, `ICowAuthentication`). Self-contained — no external dependencies. Inherit this for any new bundle. |
| `CowAuthWrapper.sol` | Extension of `CowWrapper` with EIP-712/EIP-1271 authentication, binding each order to wrapper-specific typed data. |
| `PreApprovedHashes.sol` | Abstract contract for pre-approving order hashes on-chain, enabling gasless or signature-free order submission. |
| `CowWrapperHelpers.sol` | Off-chain utility for validating wrapper chains and encoding `chainedWrapperData`. Not intended for on-chain use. |
| `ExampleWrapper.sol` | Reference implementation showing how to build a bundle on top of `CowAuthWrapper`. |

## Usage

### Just commands

Install `just` on your machine, then run `just help` to see the available commands.

### Build

```shell
just build
```

Project contracts use caret pragmas like `^0.8` so downstream projects can import them with any compatible Solidity 0.8 compiler.

### Test

```shell
just test
```

### Format

```shell
just fmt
```

### Local tooling

Foundry should be installed locally and pinned to `v1.7.0`. CI uses the same version.

Install Foundry with:

```shell
foundryup --install v1.7.0
```

Check that the expected version is active with:

```shell
forge --version
```

The output should end in `v1.7.0`.

Solhint and Slither are pinned as local development dependencies under `dev/`.

The pnpm and uv setups wait 7 days before installing newly released packages, giving more review time than a 2-day delay.

Install them with:

```shell
pnpm --dir dev install --frozen-lockfile
uv sync --project dev --locked
```

Run the pinned local tools through `just`. `just lint` checks Forge formatting and Solhint; `just slither` checks contracts under `src`.

```shell
just lint
just slither
```

### Pre-commit hooks

Install the hooks with:

```shell
just register-hooks
```

The pre-push hooks run `just lint`, `just slither`, and `just coverage-check`. You can bypass hooks with `--no-verify`, but CI remains the source of truth.

### Gas snapshots

```shell
just snapshot
```

