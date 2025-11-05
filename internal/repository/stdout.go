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
	"gorm.io/gorm"
)

// EncryptedWallet is a wallet structure with encrypted sensitive fields for export
type EncryptedWallet struct {
	Address       string    `json:"address"`
	PrivateKey    string    `json:"privateKey,omitempty"` // Encrypted
	Mnemonic      string    `json:"mnemonic,omitempty"`   // Encrypted
	HDPath        string    `json:"hdPath,omitempty"`
	Bits          int       `json:"bits,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
	HasPrivateKey bool      `json:"hasPrivateKey"` // Indicates if private key exists
	HasMnemonic   bool      `json:"hasMnemonic"`   // Indicates if mnemonic exists
	gorm.Model
}

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

// This is definetly hacky, as it ties main.go and InMemoryRepository together with the password input. But reduces diff a lot.
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

	// Confirm password
	fmt.Print("Confirm password: ")
	confirmPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println() // newline after password input
	if err != nil {
		// Zero out first password before returning
		for i := range password {
			password[i] = 0
		}
		return fmt.Errorf("error reading password confirmation: %w", err)
	}

	// Verify passwords match
	if string(password) != string(confirmPassword) {
		// Zero out both passwords before returning
		for i := range password {
			password[i] = 0
		}
		for i := range confirmPassword {
			confirmPassword[i] = 0
		}
		return fmt.Errorf("passwords do not match")
	}

	// Zero out confirm password from memory
	for i := range confirmPassword {
		confirmPassword[i] = 0
	}

	// Zero out password from memory after use
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()

	// Convert wallets to encrypted wallet structure
	encryptedWallets := make([]EncryptedWallet, 0, len(r.wallets))
	for _, wallet := range r.wallets {
		encWallet := EncryptedWallet{
			Address:       wallet.Address,
			HDPath:        wallet.HDPath,
			Bits:          wallet.Bits,
			CreatedAt:     wallet.CreatedAt,
			UpdatedAt:     wallet.UpdatedAt,
			HasPrivateKey: wallet.PrivateKey != "",
			HasMnemonic:   wallet.Mnemonic != "",
		}

		// Encrypt PrivateKey if present
		if wallet.PrivateKey != "" {
			encryptedPK, err := encryption.Encrypt(wallet.PrivateKey, string(password))
			if err != nil {
				return fmt.Errorf("error encrypting private key: %w", err)
			}
			encWallet.PrivateKey = encryptedPK
		}

		// Encrypt Mnemonic if present
		if wallet.Mnemonic != "" {
			encryptedMnemonic, err := encryption.Encrypt(wallet.Mnemonic, string(password))
			if err != nil {
				return fmt.Errorf("error encrypting mnemonic: %w", err)
			}
			encWallet.Mnemonic = encryptedMnemonic
		}

		encryptedWallets = append(encryptedWallets, encWallet)
	}

	// Convert to JSON (with Address in plain text, PrivateKey/Mnemonic encrypted)
	jsonData, err := json.MarshalIndent(encryptedWallets, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling wallets: %w", err)
	}

	// Create output directory if it doesn't exist
	outputDir := "output"
	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return fmt.Errorf("error creating output directory: %w", err)
	}

	// Write JSON file directly (addresses visible, only PK/mnemonic encrypted)
	filename := filepath.Join(outputDir, "wallets.encrypted.json")
	if err := os.WriteFile(filename, jsonData, 0600); err != nil {
		return fmt.Errorf("error writing encrypted file: %w", err)
	}

	// Zero out JSON data from memory after writing
	for i := range jsonData {
		jsonData[i] = 0
	}

	fmt.Printf("Successfully exported %d wallets to %s\n", len(r.wallets), filename)
	return nil
}
