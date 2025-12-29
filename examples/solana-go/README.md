# CubeSigner Go SDK: `solana-go` Example
This example shows how to use [`solana-go`][solana-go] library with CubeSigner Go SDK to sign Solana transactions in secure hardware.
Specifically, the example shows how to sign and send a simple value transaction from one account to another on the Solana devnet.

## Running the Example
To run the example, you need at least two Solana keys with sufficient funds in the source key. You can also optionally use a third key for pay for transaction fees. To get started, create a user session with at least `sign:solana:tx` and `manage:key:get` scopes with `cs`:

```bash
export CUBE_SIGNER_TOKEN=$(cs session create ... --output base64)
```

Then, set the source, destination, and fee payer addresses, and a SOL amount to transfer:
```
export FROM_ADDRESS=... # this is your solana key material id
export TO_ADDRESS=... # the recipient
export FEE_PAYER_ADDRESS=... # the fee payer (optional)
export AMOUNT="0.0000001" # amount to transfer in SOL
```

You are now set to run the example with:
```
go run solana-go.go
```

[solana-go]: https://github.com/gagliardetto/solana-go
[top-level README]: ../../README.md