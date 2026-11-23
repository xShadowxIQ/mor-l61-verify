# Morpheus PoC harness

Foundry mainnet-fork PoCs. Each test is self-contained: declares its own interfaces,
reads `RPC_URL` from the environment, pins a fork block, and asserts the loss.

Layout:
- `test/eth/`  — Ethereum mainnet (Capital: DepositPool, Distributor, RewardPool, L1SenderV2)
- `test/base/` — Base (Builders, LumerinDiamond facets)
- `test/arb/`  — Arbitrum (L2MessageReceiver, L2TokenReceiverV2)

Run locally: `RPC_URL=<rpc> forge test --match-path 'test/eth/*' -vvv`
CI: every push runs all three jobs.
