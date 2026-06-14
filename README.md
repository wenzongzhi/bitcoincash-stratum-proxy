# Bitcoin Cash Stratum Proxy

A lightweight Stratum V1 proxy for solo mining Bitcoin Cash with a BCHN full
node. It builds miner-specific coinbase transactions, validates submitted
shares locally, and submits valid block candidates to BCHN.

The project is intended for trusted local networks and small ASIC miners such
as Bitaxe and NerdQaxe. It is not a public pool server and does not implement
accounts, reward accounting, TLS, or distributed pool infrastructure.

## Features

- Bitcoin Cash mainnet solo mining
- Testnet4, Scalenet, Chipnet, and Regtest support
- Per-connection `extranonce1`
- Miner-specific payout addresses
- Legacy, prefixed CashAddr, and prefixless CashAddr support
- Empty-block and transaction-bearing block templates
- Correct Stratum merkle branches that exclude the coinbase hash
- BIP310 version rolling
- BIP310 minimum-difficulty, subscribe-extranonce, and info negotiation
- Standard Stratum share error codes
- Duplicate share detection
- Optional block proposal validation before `submitblock` (disabled by default)
- BCHN `workid` forwarding

## Requirements

- Python 3.10 or newer
- A synchronized BCHN full node with JSON-RPC enabled
- An ASIC miner with Stratum V1 support

Install the Python dependencies:

```powershell
python -m pip install requests base58 ecashaddress
```

## Mainnet

Edit the configuration section near the top of
`bitcoincash_stratum_proxy.py`:

```python
RPC_USER = "your_rpc_user"
RPC_PASS = "your_rpc_password"
RPC_HOST = "127.0.0.1"
RPC_PORT = 8332

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 3333

DEFAULT_PAYOUT_ADDRESS = "bitcoincash:your_mainnet_address"
```

Example BCHN configuration:

```ini
server=1
rpcuser=your_rpc_user
rpcpassword=your_rpc_password
rpcallowip=127.0.0.1
```

Start the proxy:

```powershell
python .\bitcoincash_stratum_proxy.py
```

## Test Networks

Use `bitcoincash-stratum-proxy-testnet.py` for all supported test networks.
Configuration is read from environment variables.

| Network | `BCH_TEST_NETWORK` | Default RPC port | Default Stratum port | CashAddr prefix |
| --- | --- | ---: | ---: | --- |
| Testnet4 | `testnet4` | 28332 | 3334 | `bchtest:` |
| Scalenet | `scale` or `scalenet` | 38332 | 3335 | `bchtest:` |
| Chipnet | `chip` or `chipnet` | 48332 | 3336 | `bchtest:` |
| Regtest | `regtest` | 18443 | 3337 | `bchreg:` |

Example for Testnet4:

```powershell
$env:BCH_TEST_NETWORK = "testnet4"
$env:BCH_RPC_USER = "your_rpc_user"
$env:BCH_RPC_PASSWORD = "your_rpc_password"
$env:BCH_PAYOUT_ADDRESS = "bchtest:your_testnet_address"
python .\bitcoincash-stratum-proxy-testnet.py
```

Example for Regtest:

```powershell
$env:BCH_TEST_NETWORK = "regtest"
$env:BCH_RPC_USER = "your_rpc_user"
$env:BCH_RPC_PASSWORD = "your_rpc_password"
$env:BCH_PAYOUT_ADDRESS = "bchreg:your_regtest_address"
python .\bitcoincash-stratum-proxy-testnet.py
```

Optional overrides:

```powershell
$env:BCH_RPC_HOST = "127.0.0.1"
$env:BCH_RPC_PORT = "28332"
$env:BCH_STRATUM_HOST = "0.0.0.0"
$env:BCH_STRATUM_PORT = "3334"
```

The testnet proxy calls `getblockchaininfo` at startup and exits if the BCHN
chain does not match `BCH_TEST_NETWORK`.

## ASIC Configuration

Set the ASIC pool URL to the proxy host and Stratum port:

```text
stratum+tcp://PROXY_IP:3333
```

Use the payout address as the Stratum username. An optional worker suffix may
follow the address:

```text
bitcoincash:q...worker-address
bitcoincash:q...worker-address.bitaxe-01
```

For public test networks, use a `bchtest:` address. For Regtest, use a
`bchreg:` address. The password field is accepted but not used.

If the submitted username is not a valid address, the proxy uses
`DEFAULT_PAYOUT_ADDRESS` or `BCH_PAYOUT_ADDRESS`. Authorization fails when
both addresses are invalid.

## Stratum V1 Support

Client requests:

- `mining.configure`
- `mining.subscribe`
- `mining.authorize`
- `mining.submit`
- `mining.extranonce.subscribe`
- `mining.suggest_difficulty`
- `mining.get_transactions`
- `mining.multi_version`
- `mining.ping`
- `client.get_version`

Server notifications:

- `mining.set_difficulty`
- `mining.set_extranonce`
- `mining.notify`

Supported BIP310 extensions:

- `version-rolling`
- `minimum-difficulty`
- `subscribe-extranonce`
- `info`

The proxy uses the standard Stratum share error codes:

| Code | Meaning |
| ---: | --- |
| 20 | Other or unknown error |
| 21 | Job not found or stale |
| 22 | Duplicate share |
| 23 | Low difficulty share |
| 24 | Unauthorized worker |
| 25 | Not subscribed |

## Mining Flow

```text
ASIC miner                    Proxy                         BCHN
    |                           |                            |
    | mining.configure          |                            |
    | mining.subscribe          |                            |
    | mining.authorize          |                            |
    |-------------------------->|                            |
    |                           | getblocktemplate           |
    |                           |--------------------------->|
    |                           |<---------------------------|
    | mining.set_difficulty     |                            |
    | mining.notify             |                            |
    |<--------------------------|                            |
    |                           |                            |
    | mining.submit             |                            |
    |-------------------------->|                            |
    |                           | validate share             |
    |                           | proposal / submitblock     |
    |                           |--------------------------->|
    |<--------------------------|                            |
```

The proxy polls BCHN for block templates. A new previous block hash produces a
job with `clean_jobs=true`. Mempool-only changes produce a new job without
invalidating all older jobs.

Each miner receives a coinbase transaction containing its own payout script
and the connection-specific `extranonce1`. The miner supplies `extranonce2`,
`ntime`, `nonce`, and optionally BIP310 version bits.

## Validation and Submission

The proxy performs the following checks before accepting a share:

1. Subscription and authorization state
2. Job availability
3. Duplicate submission detection
4. Extranonce, timestamp, nonce, and version-bit format
5. Coinbase and merkle-root reconstruction
6. Announced Stratum share difficulty
7. BCH network target

When a share reaches the network target, the proxy builds the full block and
calls `submitblock`. Optional GBT proposal validation is available for
diagnostics but is disabled by default to avoid delaying a solved block with
an extra RPC round trip. When enabled, proposal transport failures are
fail-open, while explicit proposal rejection stops submission.

After BCHN accepts a block, the proxy returns the normal successful
`mining.submit` response:

```json
{"id":123,"result":true,"error":null}
```

Current Bitaxe and NerdAxe firmware detects a block candidate locally by
comparing the share difficulty with the network target and displays its native
block-found notification. No additional non-standard Stratum message is
required.

## Tests

Run the complete test suite:

```powershell
python -m unittest discover -s test -v
```

Run syntax checks:

```powershell
python -m py_compile `
  .\bitcoincash_stratum_proxy.py `
  .\bitcoincash-stratum-proxy-testnet.py
```

## Security Notes

- Run the proxy on a trusted LAN.
- Do not expose the Stratum or BCHN RPC ports directly to the internet.
- Use strong BCHN RPC credentials.
- Restrict BCHN `rpcallowip` to the proxy host.
- This proxy does not encrypt Stratum V1 traffic.

## License

Apache License 2.0. See `LICENSE`.
