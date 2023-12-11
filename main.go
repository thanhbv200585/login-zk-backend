package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
)

type KeyPair struct {
	PublicKey  []byte `json:"public_key"`
	PrivateKey []byte `json:"private_key"`
}

func main() {
	// 2. Sparse Merkle Tree

	ctx := context.Background()

	// Tree storage
	store := memory.NewMemoryStorage()

	// Generate a new MerkleTree with 32 levels
	mt, _ := merkletree.NewMerkleTree(ctx, store, 32)

	// Add a leaf to the tree with index 1 and value 10
	index1 := big.NewInt(1)
	value1 := big.NewInt(10)
	mt.Add(ctx, index1, value1)

	// Add another leaf to the tree
	index2 := big.NewInt(2)
	value2 := big.NewInt(15)
	mt.Add(ctx, index2, value2)

	// Proof of membership of a leaf with index 1
	proofExist, value, _ := mt.GenerateProof(ctx, index1, mt.Root())

	fmt.Println("Proof of membership:", proofExist.Existence)
	fmt.Println("Value corresponding to the queried index:", value)

	// Proof of non-membership of a leaf with index 4
	proofNotExist, _, _ := mt.GenerateProof(ctx, big.NewInt(4), mt.Root())

	fmt.Println("Proof of membership:", proofNotExist.Existence)
	http.HandleFunc("/api/generate-key", generateBabyJubJubKeys)
	http.ListenAndServe(":8080", nil)
}

func generateBabyJubJubKeys(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	// Generate BabyJubJub private key randomly
	babyJubjubPrivKey := babyjub.NewRandPrivKey()

	// Generate public key from private key
	babyJubjubPubKey := babyJubjubPrivKey.Public()

	pubKeyBytes, _ := json.Marshal(babyJubjubPubKey)
	privKeyBytes, _ := json.Marshal(babyJubjubPrivKey)

	keyPair := KeyPair{
		PublicKey:  pubKeyBytes,
		PrivateKey: privKeyBytes,
	}
	w.Header().Set("Content-Type", "application/json")

	// Send the JSON bytes in the response body
	keyPairBytes, err := json.Marshal(keyPair)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set content type to application/json
	w.Header().Set("Content-Type", "application/json")

	// Send the JSON bytes in the response body
	w.Write(keyPairBytes)
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}
