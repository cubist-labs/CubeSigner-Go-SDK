# CubeSigner Go SDK: `go-ethereum` Example
This example shows how the CubeSigner Go SDK can be used to sign transactions on EVM-based chains with [`go-ethereum`][go-ethereum].
Specifically, the example shows how to sign and send a simple `ETH` transaction from one account to another.

## Running the Example
To run the example, you need two EVM keys with sufficient funds in the source key. Create a user session with at least `sign:evm:tx` and `manage:key:get` scopes with `cs`:

```bash
export CUBE_SIGNER_TOKEN=$(cs session create ... --output base64)
```

Then, set the source and destination addresses, and a JSON-RPC provider
```
export FROM_ADDRESS=0x... # this is your secp key material id
export TO_ADDRESS=0x... # the recipient
export AMOUNT=0.0000001 # amount to transfer in eth
export RPC_PROVIDER=https://... # A JSON-RPC provider
```

You are now set to run the example with:
```
go run go-ethereum.go
```

[go-ethereum]: https://github.com/ethereum/go-ethereum
[top-level README]: ../../README.md