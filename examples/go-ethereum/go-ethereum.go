package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/cubist-labs/cubesigner-go-sdk/client"
	"github.com/cubist-labs/cubesigner-go-sdk/models"
	"github.com/cubist-labs/cubesigner-go-sdk/session"
	"github.com/cubist-labs/cubesigner-go-sdk/utils/ref"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

var (
	FromAddress            = os.Getenv("FROM_ADDRESS")      // sender address
	ToAddress              = os.Getenv("TO_ADDRESS")        // recipient address
	RpcProvider            = os.Getenv("RPC_PROVIDER")      // RPC provider URL
	EthAmountStr           = os.Getenv("AMOUNT")            // amount to transfer in ETH
	CubeSignerSessionToken = os.Getenv("CUBE_SIGNER_TOKEN") // CubeSigner session token (base64 encoded)
)

func main() {
	amount, ok := new(big.Int).SetString(fmt.Sprintf("%.0f", parseEthToWei(EthAmountStr)), 10)
	if !ok {
		log.Fatal("Invalid amount")
	}

	// create a CubeSigner client from the provided session token
	manager := session.NewMemorySessionManager(decodeSessionToken(CubeSignerSessionToken))
	apiClient, err := client.NewApiClient(manager)
	if err != nil {
		log.Fatal("Failed to create CubeSigner API client: ", err)
	}

	// connect to RPC provider
	ethClient, err := ethclient.Dial(RpcProvider)
	if err != nil {
		log.Fatal("Failed to connect to the RPC Provider: ", err)
	}

	// get nonce and prepare transaction
	nonce, err := ethClient.PendingNonceAt(context.Background(), common.HexToAddress(FromAddress))
	if err != nil {
		log.Fatal("Failed to get nonce: ", err)
	}
	tip, feeCap := getSuggestedGasFees(ethClient)
	TxBody := models.TypedTransaction{}
	err = TxBody.FromTypedTransactionEip1559(models.TypedTransactionEip1559{
		To:                   ref.Of(ToAddress),
		Nonce:                ref.Of(fmt.Sprintf("0x%x", nonce)), // nonce in hex
		Type:                 "0x02",                             // EIP-1559 transaction
		Gas:                  ref.Of("0x5208"),                   // 21000
		MaxFeePerGas:         ref.Of("0x" + feeCap.Text(16)),
		MaxPriorityFeePerGas: ref.Of("0x" + tip.Text(16)),
		Value:                ref.Of("0x" + amount.Text(16)), // amount in hex
	})
	if err != nil {
		log.Fatal("Failed to prepare the transaction body: ", err)
	}
	eth1Request := models.Eth1SignRequest{
		ChainId: getChainID(ethClient),
		Tx:      TxBody,
	}

	// sign with CubeSigner
	signResponse, err := apiClient.EvmSign(FromAddress, eth1Request)
	if err != nil {
		log.Fatal("Failed to sign the transaction: ", err)
	}
	rlpBytes := decodeRlpHex(signResponse.ResponseData.RlpSignedTx)

	// Unmarshal the typed transaction
	tx := new(types.Transaction)
	err = tx.UnmarshalBinary(rlpBytes)
	if err != nil {
		log.Fatal("Failed to unmarshal typed transaction: ", err)
	}

	receipt, err := ethClient.SendTransactionSync(context.Background(), tx, nil)
	if err != nil {
		log.Fatal("Failed to send the transaction: ", err)
	}
	fmt.Printf("Transaction sent! Tx Hash: %s\n", receipt.TxHash.Hex())
}

// decodeRlpHex decodes a hex-encoded RLP transaction string to bytes
func decodeRlpHex(rlpTx string) []byte {
	// If the string has a "0x" prefix, strip it
	rlpHex := rlpTx
	if len(rlpHex) >= 2 && rlpHex[:2] == "0x" {
		rlpHex = rlpHex[2:]
	}

	// Decode hex string to bytes
	rlpBytes, err := hex.DecodeString(rlpHex)
	if err != nil {
		log.Fatal("Failed to decode RLP hex: ", err)
	}

	return rlpBytes
}

// getChainID retrieves the chain ID from the Ethereum client
func getChainID(ethClient *ethclient.Client) int64 {
	chainID, err := ethClient.NetworkID(context.Background())
	if err != nil {
		log.Fatal("Failed to get chain ID: ", err)
	}
	return chainID.Int64()
}

// parseEthToWei converts an ETH amount in string format to Wei as a float64
func parseEthToWei(ethStr string) float64 {
	var eth float64
	_, err := fmt.Sscanf(ethStr, "%f", &eth)
	if err != nil {
		log.Fatal("Invalid ETH amount: ", err)
	}
	return eth * 1e18
}

// getSuggestedGasFees retrieves the suggested gas tip and fee cap from the Ethereum client
func getSuggestedGasFees(ethClient *ethclient.Client) (*big.Int, *big.Int) {
	tip, err := ethClient.SuggestGasTipCap(context.Background())
	if err != nil {
		log.Fatal("Failed to get gas tip cap: ", err)
	}
	feeCap, err := ethClient.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal("Failed to get gas fee cap: ", err)
	}
	return tip, feeCap
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
