package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"strconv"

	"github.com/cubist-labs/cubesigner-go-sdk/client"
	"github.com/cubist-labs/cubesigner-go-sdk/models"
	"github.com/cubist-labs/cubesigner-go-sdk/session"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
	confirm "github.com/gagliardetto/solana-go/rpc/sendAndConfirmTransaction"
	"github.com/gagliardetto/solana-go/rpc/ws"
)

var (
	FromAddress            = os.Getenv("FROM_ADDRESS")      // sender address
	ToAddress              = os.Getenv("TO_ADDRESS")        // recipient address
	FeePayerAddress        = os.Getenv("FEE_PAYER_ADDRESS") // optional, can be the same as FromAddress
	SolAmountStr           = os.Getenv("AMOUNT")            // amount to transfer is SOL
	CubeSignerSessionToken = os.Getenv("CUBE_SIGNER_TOKEN") // CubeSigner session token (base64 encoded)
)

// this example runs on Solana devnet
const RpcProvider = "https://api.devnet.solana.com"

func main() {
	// parse amount
	const LamportsPerSOL = 1_000_000_000
	solAmount, err := strconv.ParseFloat(SolAmountStr, 64)
	if err != nil {
		log.Fatal("Invalid amount:", err)
	}
	lamports := uint64(solAmount * LamportsPerSOL)

	// create a CubeSigner client from the provided session token
	manager := session.NewMemorySessionManager(decodeSessionToken(CubeSignerSessionToken))
	if err != nil {
		log.Fatal("Failed to create CubeSigner session manager: ", err)
	}
	apiClient, err := client.NewApiClient(manager)
	if err != nil {
		log.Fatal("Failed to create CubeSigner API client: ", err)
	}

	// solana rpcClient
	rpcClient := rpc.New(RpcProvider)

	latestBlockHashResp, err := rpcClient.GetLatestBlockhash(context.Background(), rpc.CommitmentFinalized)
	if err != nil {
		log.Fatal("Failed to get recent blockhash: ", err)
	}
	latestBlockHash := latestBlockHashResp.Value.Blockhash

	fromPub := solana.MustPublicKeyFromBase58(FromAddress)
	toPub := solana.MustPublicKeyFromBase58(ToAddress)
	feePayerPub := solana.MustPublicKeyFromBase58(FeePayerAddress)

	// print initial balances
	getAndPrintSolBalance(rpcClient, FromAddress)
	getAndPrintSolBalance(rpcClient, ToAddress)
	if !fromPub.Equals(feePayerPub) {
		getAndPrintSolBalance(rpcClient, FeePayerAddress)
	}

	// build transaction
	tx, err := solana.NewTransaction(
		[]solana.Instruction{
			system.NewTransferInstruction(
				lamports,
				fromPub,
				toPub,
			).Build(),
		},
		latestBlockHash,
		solana.TransactionPayer(feePayerPub),
	)
	if err != nil {
		log.Fatal("Failed to build transaction:", err)
	}

	// serialize the transaction message
	txMessageBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		log.Fatal("Failed to serialize transaction message:", err)
	}
	messageBase64 := base64.StdEncoding.EncodeToString(txMessageBytes)

	// sign with CubeSigner
	signResponse, err := apiClient.SolanaSign(FromAddress, models.SolanaSignRequest{MessageBase64: messageBase64})
	if err != nil {
		log.Fatal("Failed to sign the transaction: ", err)
	}
	fromSigBytes := getSigBytes(signResponse.ResponseData.Signature)

	tx.Signatures = append(tx.Signatures, solana.Signature(fromSigBytes))

	// if fee payer differs from sender, also sign for fee payer
	if !fromPub.Equals(feePayerPub) {
		feePayerSignResp, err := apiClient.SolanaSign(FeePayerAddress, models.SolanaSignRequest{MessageBase64: messageBase64})
		if err != nil {
			log.Fatal("Failed to sign fee payer:", err)
		}
		feePayerSigBytes := getSigBytes(feePayerSignResp.ResponseData.Signature)

		tx.Signatures = append(tx.Signatures, solana.Signature(feePayerSigBytes))
	}

	// send and wait for transaction
	sig, error := confirm.SendAndConfirmTransaction(context.Background(), rpcClient, getWsClient(), tx)
	if error != nil {
		log.Fatal("Failed to send transaction:", error)
	}
	log.Printf("Transaction sent! Tx Signature: %s\n", sig.String())

	// print final balances
	getAndPrintSolBalance(rpcClient, FromAddress)
	getAndPrintSolBalance(rpcClient, ToAddress)
	if !fromPub.Equals(feePayerPub) {
		getAndPrintSolBalance(rpcClient, FeePayerAddress)
	}
}

// getWsClient creates and returns a WebSocket client for Solana. This client is used to confirm transactions.
func getWsClient() *ws.Client {
	// Create a new WS client (used for confirming transactions)
	wsClient, err := ws.Connect(context.Background(), rpc.DevNet_WS)
	if err != nil {
		panic(err)
	}
	return wsClient
}

// getAndPrintSolBalance retrieves and prints the SOL balance of the given address.
func getAndPrintSolBalance(rpcClient *rpc.Client, address string) {
	pubKey := solana.MustPublicKeyFromBase58(address)
	balanceResp, err := rpcClient.GetBalance(context.Background(), pubKey, rpc.CommitmentFinalized)
	if err != nil {
		log.Fatal("Failed to get balance:", err)
	}
	const LamportsPerSOL = 1_000_000_000
	solBalance := float64(balanceResp.Value) / LamportsPerSOL
	log.Printf("Balance of %s: %f SOL\n", address, solBalance)
}

// getSigBytes decodes a hex-encoded signature string into bytes.
func getSigBytes(sigHex string) []byte {
	if len(sigHex) >= 2 && sigHex[:2] == "0x" {
		sigHex = sigHex[2:]
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		log.Fatal("Failed to decode signature:", err)
	}
	return sigBytes
}

// decodeSessionToken decodes a base64-encoded session token string into SessionData
func decodeSessionToken(tokenStr string) *session.SessionData {
	decodedBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		log.Fatal("Failed to decode session token: ", err)
	}

	var sessionData session.SessionData
	if err := json.Unmarshal(decodedBytes, &sessionData); err != nil {
		log.Fatal("Failed to unmarshal session data: ", err)
	}
	return &sessionData
}
