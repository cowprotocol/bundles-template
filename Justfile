set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set quiet # Doesn't print the command that is being run

COVERAGE_MIN := env_var_or_default("COVERAGE_MIN", "100")
SOLHINT := "dev/node_modules/.bin/solhint" # Binary path for local Solhint installation
JUST := just_executable()

# Runs `just help`
default: help

# Register pre-push hooks
register-hooks:
    uv run --project dev pre-commit install --hook-type pre-push

# Show available recipes
help:
    {{JUST}} --list

# Compile contracts
build:
    forge build

# Compile all contracts
build-all:
    forge build --force

# Format Solidity sources
fmt:
    forge fmt

# Check formatting and run `solhint` on `src`/`script`/`test`
lint:
    forge fmt --check
    {{SOLHINT}} --max-warnings 0 '**/*.sol'

# Run Slither static analysis on `src`
slither:
    uv run --project dev slither src --config-file slither.config.json

# Run tests
test:
    forge test -vvv --show-progress --gas-snapshot-check true

# Print coverage summary
coverage-summary:
    forge coverage --no-match-coverage "^(test|script|lib)/" --report summary

# Generate lcov coverage report
coverage-lcov:
    forge coverage --no-match-coverage "^(test|script|lib)/" --report lcov

# Fail if the minimum of all four coverage metrics (lines/statements/branches/funcs) on the `Total` row is below `COVERAGE_MIN` (default `100`)
coverage-check:
    @{{JUST}} coverage-summary > coverage.txt
    cat coverage.txt
    # Fields on the `| Total | ... |` row are: $4=lines, $7=statements, $10=branches, $13=funcs (whitespace-split, `%` stripped)
    awk -v threshold={{COVERAGE_MIN}} '\
        BEGIN { labels[4]="lines"; labels[7]="statements"; labels[10]="branches"; labels[13]="funcs"; min=100; below="" } \
        /^\| Total/ { \
            found=1; \
            for (i=4; i<=13; i+=3) { \
                gsub(/%/, "", $i); \
                v=$i+0; \
                if (v < min) min=v; \
                if (v < threshold) below = below sprintf("  %-12s %s%%\n", labels[i] ":", $i); \
            } \
        } \
        END { \
            if (!found) { print "Failed to extract coverage percentage."; exit 1 } \
            if (min < threshold) { printf "\nMetrics below minimum threshold of %s%%:\n%s\n", threshold, below; exit 1 } \
        }' coverage.txt
    rm coverage.txt

# Generate gas snapshots
snapshot:
    forge snapshot --desc --show-progress

# Serve signing-test.html over HTTP so MetaMask can inject window.ethereum (file:// pages don't work)
serve:
    python3 -m http.server 8080 --bind 127.0.0.1

# Start Anvil mainnet fork
anvil-fork:
    anvil --fork-url "$RPC_URL_1"

# Deploy ExampleWrapper to Anvil fork and register it as a solver.
# Reads PRIVATE_KEY from env (defaults to Anvil account 0).
# Set RPC_URL to override the default http://localhost:8545.
anvil-deploy:
    #!/usr/bin/env bash
    set -euo pipefail
    RPC="${RPC_URL:-http://localhost:8545}"
    SETTLEMENT="0x9008D19f58AAbD9eD0D60971565AA8510560ab41"
    AUTHENTICATOR="0x2c4c28DDBdAc9C5E7055b4C863b72eA0149D8aFE"

    echo "==> Deploying ExampleWrapper..."
    FORGE_OUT=$(forge create src/ExampleWrapper.sol:ExampleWrapper \
        --rpc-url "$RPC" \
        --private-key "${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}" \
        --broadcast \
        --constructor-args "$SETTLEMENT" 2>&1) || { echo "forge create failed:"; echo "$FORGE_OUT"; exit 1; }
    echo "$FORGE_OUT"
    WRAPPER=$(echo "$FORGE_OUT" | grep -oP '(?<=Deployed to: )0x[0-9a-fA-F]+')
    echo "ExampleWrapper deployed at: $WRAPPER"

    echo "==> Fetching authenticator manager..."
    MANAGER=$(cast call --rpc-url "$RPC" "$AUTHENTICATOR" "manager()(address)")
    echo "Manager: $MANAGER"

    echo "==> Impersonating manager and registering wrapper as solver..."
    cast rpc --rpc-url "$RPC" anvil_impersonateAccount "$MANAGER"
    cast send --rpc-url "$RPC" --from "$MANAGER" --unlocked \
        "$AUTHENTICATOR" "addSolver(address)" "$WRAPPER"
    cast rpc --rpc-url "$RPC" anvil_stopImpersonatingAccount "$MANAGER"

    echo ""
    echo "Done. Paste this wrapper address into signing-test.html:"
    echo "  $WRAPPER"

# Run build, lint, slither, coverage-check, snapshot
all: build lint slither coverage-check snapshot
