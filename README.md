# web3.zig

A collection of utilities for interacting with a local or remote ethereum node. Similar to the javascript
frameworks [web3.js](https://web3js.readthedocs.io/en/v1.10.0/) or [ethers.js](https://docs.ethers.org/v5/).

No external dependencies aside from "std".

**This library is currently incomplete and probably not suitable for production use.**

## Implementation Roadmap

This is a list of what has been implemented and what is planned.

### Json RPC

| method                                  | implementation status |
| --------------------------------------- | --------------------- |
| web3_clientVersion                      | ✅                    |
| web3_sha3                               | ✅                    |
| net_version                             | ✅                    |
| net_listening                           | ✅                    |
| net_peerCount                           | ✅                    |
| eth_protocolVersion                     | ✅                    |
| eth_syncing                             | ✅                    |
| eth_coinbase                            | ✅                    |
| eth_chainId                             | ✅                    |
| eth_mining                              | ✅                    |
| eth_hashrate                            | ✅                    |
| eth_gasPrice                            | ✅                    |
| eth_accounts                            | ✅                    |
| eth_blockNumber                         | ✅                    |
| eth_getBalance                          | ✅                    |
| eth_getStorageAt                        | ✅                    |
| eth_getTransactionCount                 | ✅                    |
| eth_getBlockTransactionCountByHash      | ✅                    |
| eth_getBlockTransactionCountByNumber    | ✅                    |
| eth_getUncleCountByBlockHash            | ✅                    |
| eth_getUngleCountByBlockNumber          | ✅                    |
| eth_getCode                             | ✅                    |
| eth_sign                                | ✅                    |
| eth_signTransaction                     | ✅                    |
| eth_sendTransaction                     | ✅                    |
| eth_sendRawTransaction                  | ✅                    |
| eth_call                                | ✅                    |
| eth_estimateGas                         | ✅                    |
| eth_getBlockByHash                      | ✅                    |
| eth_getBlockByNumber                    | ✅                    |
| eth_getTransactionByHash                | ✅                    |
| eth_getTransactionByBlockHashAndIndex   | ✅                    |
| eth_getTransactionByBlockNumberAndIndex | ✅                    |
| eth_getTransactionReceipt               | ✅                    |
| eth_getUncleByBlockHashAndIndex         | ✅                    |
| eth_getUncleByBlockNumberAndIndex       | ✅                    |
| eth_newFilter                           | ❌                    |
| eth_newBlockFilter                      | ❌                    |
| eth_newPendingTransactionFilter         | ❌                    |
| eth_uninstallFilter                     | ❌                    |
| eth_getFilterChanges                    | ❌                    |
| eth_getFilterLogs                       | ❌                    |
| eth_getLogs                             | ✅                    |

#### Transports

- ✅ HTTP
- ❌ WebSocket
- ❌ IPC

### ABI Types

- ✅ uint\<M>
- ✅ int\<M>
- ✅ address
- ✅ bool
- ✅ \<type>[M]
- ✅ \<type>[]
- ✅ string
- ❌ fixed\<M>x\<N>
- ❌ ufixed\<M>x\<N>
- ✅ function
- ✅ bytes\<M>
- ✅ bytes
- ✅ (T1,T2,...,Tn) (aka tuples/structs)

### Features

- ✅ JSON RPC communication
- ✅ ABI encoding/decoding
- ✅ ABI parsing (JSON)
- ✅ Abstracted contract interaction (partially implemented)
- ❌ Async support (not available in Zig 0.11.0 anyway)
- ✅ Local account features (signing transactions, HD wallets, etc.)
- ❌ Log and transaction filters
- ❌ Abstracted contract deployment
- ❌ RLP encoding/decoding (and by extension transaction encoding/decoding)
- ❌ Native ENS support
- ❌ Documentation
- ❌ Comprehensive tests

## License

MIT - Copyright (c) 2023, Kane Wallmann

## Installation

This library exports a module that can be included in your project via Zig's package manager.

Add it as a dependency to your `build.zig.zon` like so:

```
...
    .dependencies = .{
        .web3 = .{
            .url = "https://github.com/kanewallmann/web3.zig/archive/refs/heads/master.tar.gz",
        },
    },
...
```

In your `build.zig` file add the module to your build by adding the lines:

```c
    const web3 = b.dependency("web3", .{ .target = target, .optimize = optimize });
    exe.addModule("web3", web3.module("web3"));
```

Then run `zig build`.

Zig will complain about the hash being incorrect:

```
note: expected .hash = "12201309cabc8d4c7d5482c7f19754f1f7f779e3cae525a4e6c9ea0e0a824a0bfe69",
```

Copy that into your `build.zig.zon` file like so:

```
...
    .dependencies = .{
        .web3 = .{
            .url = "https://github.com/kanewallmann/web3.zig/archive/refs/heads/master.tar.gz",
            .hash = "12201309cabc8d4c7d5482c7f19754f1f7f779e3cae525a4e6c9ea0e0a824a0bfe69",
        },
    },
...
```

And then you are ready to `@import("web3")` in your project.


## Examples

There are a few examples under `src/examples`. They can be run with `zig build example_{example_name} -- {rpc_endpoint}` where 
`{example_name}` is the name of one of the examples and `{rpc_endpoint}` is an RPC endpoint URI. (Currently only HTTP transport
is implemented)

Example:

```bash
zig build example_erc20 -- http://localhost:8545
```