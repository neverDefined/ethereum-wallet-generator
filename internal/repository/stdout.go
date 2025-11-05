package repository

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/planxnx/ethereum-wallet-generator/internal/encryption"
	"github.com/planxnx/ethereum-wallet-generator/wallets"
	"golang.org/x/term"
)

type InMemoryRepository struct {
	walletsMu sync.Mutex
	wallets   []*wallets.Wallet
}

func NewInMemoryRepository() Repository {
	return &InMemoryRepository{
		wallets: make([]*wallets.Wallet, 0),
	}
}

func (r *InMemoryRepository) Insert(wallet *wallets.Wallet) error {
	r.walletsMu.Lock()
	defer r.walletsMu.Unlock()

	// Set CreatedAt and UpdatedAt for in-memory wallets
	now := time.Now()
	if wallet.CreatedAt.IsZero() {
		wallet.CreatedAt = now
	}
	wallet.UpdatedAt = now

	r.wallets = append(r.wallets, wallet)
	return nil
}

func (r *InMemoryRepository) Result() []*wallets.Wallet {
	return r.wallets
}

func (r *InMemoryRepository) Close() error {
	defer func() {
		// Zero out sensitive data from memory
		r.walletsMu.Lock()
		defer r.walletsMu.Unlock()

		for _, wallet := range r.wallets {
			// Clear sensitive fields
			if wallet != nil {
				wallet.PrivateKey = ""
				wallet.Mnemonic = ""
				wallet.Address = ""
				wallet.HDPath = ""
			}
		}
		// Clear the slice
		r.wallets = nil
	}()

	if len(r.wallets) == 0 {
		return nil
	}

	// Prompt for password
	fmt.Print("Enter password to encrypt wallets: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println() // newline after password input
	if err != nil {
		return fmt.Errorf("error reading password: %w", err)
	}
	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	// Zero out password from memory after use
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()

	// Convert wallets to JSON
	jsonData, err := json.MarshalIndent(r.wallets, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling wallets: %w", err)
	}

	// Zero out JSON data from memory after encryption
	defer func() {
		for i := range jsonData {
			jsonData[i] = 0
		}
	}()

	// Encrypt JSON
	encrypted, err := encryption.Encrypt(string(jsonData), string(password))
	if err != nil {
		return fmt.Errorf("error encrypting wallets: %w", err)
	}

	// Create output directory if it doesn't exist
	outputDir := "output"
	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return fmt.Errorf("error creating output directory: %w", err)
	}

	// Write to file in output directory
	filename := filepath.Join(outputDir, "wallets.encrypted.json")
	if err := os.WriteFile(filename, []byte(encrypted), 0600); err != nil {
		return fmt.Errorf("error writing encrypted file: %w", err)
	}

	fmt.Printf("Successfully exported %d wallets to %s\n", len(r.wallets), filename)
	return nil
}
