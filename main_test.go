package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/planxnx/ethereum-wallet-generator/internal/encryption"
	"github.com/planxnx/ethereum-wallet-generator/internal/repository"
	"github.com/planxnx/ethereum-wallet-generator/wallets"
)

// TestEndToEndEncryptionFlow tests the complete flow from wallet creation to export and decryption
func TestEndToEndEncryptionFlow(t *testing.T) {
	testDir := "test_output_e2e"
	defer os.RemoveAll(testDir)

	// Step 1: Create wallets (simulating generation)
	repo := repository.NewInMemoryRepository().(*repository.InMemoryRepository)

	testWallets := []*wallets.Wallet{
		{
			Address:    "0x1111111111111111111111111111111111111111",
			PrivateKey: "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
			Mnemonic:   "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12",
			HDPath:     "m/44'/60'/0'/0",
			Bits:       128,
		},
		{
			Address:    "0x2222222222222222222222222222222222222222",
			PrivateKey: "b2c3d4e5f6a789012345678901234567890abcdef1234567890abcdef12345678",
			Mnemonic:   "",
			HDPath:     "",
			Bits:       0,
		},
	}

	for _, wallet := range testWallets {
		if err := repo.Insert(wallet); err != nil {
			t.Fatalf("Failed to insert wallet: %v", err)
		}
	}

	// Step 2: Export wallets (simulating Close() behavior)
	password := "secure-test-password-123"
	_, err := exportWalletsForTesting(repo, password, testDir)
	if err != nil {
		t.Fatalf("Failed to export wallets: %v", err)
	}

	// Verify export file exists
	exportFile := filepath.Join(testDir, "test_wallets.encrypted.json")
	if _, err := os.Stat(exportFile); os.IsNotExist(err) {
		t.Fatal("Export file was not created")
	}

	// Step 3: Read and decrypt the file (simulating -decrypt command)
	fileData, err := os.ReadFile(exportFile)
	if err != nil {
		t.Fatalf("Failed to read export file: %v", err)
	}

	var encryptedWallets []repository.EncryptedWallet
	if err := json.Unmarshal(fileData, &encryptedWallets); err != nil {
		t.Fatalf("Failed to parse encrypted JSON: %v", err)
	}

	// Decrypt wallets
	decryptedWallets, err := decryptWalletsForTesting(encryptedWallets, password)
	if err != nil {
		t.Fatalf("Failed to decrypt wallets: %v", err)
	}

	// Step 4: Verify data integrity
	if len(decryptedWallets) != len(testWallets) {
		t.Fatalf("Wallet count mismatch: expected %d, got %d", len(testWallets), len(decryptedWallets))
	}

	for i, decrypted := range decryptedWallets {
		original := testWallets[i]
		if decrypted.Address != original.Address {
			t.Errorf("Wallet %d: Address mismatch", i)
		}
		if decrypted.PrivateKey != original.PrivateKey {
			t.Errorf("Wallet %d: PrivateKey mismatch", i)
		}
		if decrypted.Mnemonic != original.Mnemonic {
			t.Errorf("Wallet %d: Mnemonic mismatch", i)
		}
	}
}

// TestDataIntegrityAfterMultipleEncryptions ensures data doesn't degrade
func TestDataIntegrityAfterMultipleEncryptions(t *testing.T) {
	testWallet := &wallets.Wallet{
		Address:    "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
		PrivateKey: "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
		Mnemonic:   "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12",
		HDPath:     "m/44'/60'/0'/0",
		Bits:       128,
	}

	password := "test-password"
	testDir := "test_output_e2e"
	defer os.RemoveAll(testDir)

	repo := repository.NewInMemoryRepository().(*repository.InMemoryRepository)
	if err := repo.Insert(testWallet); err != nil {
		t.Fatalf("Failed to insert wallet: %v", err)
	}

	// Encrypt and decrypt multiple times
	for i := 0; i < 5; i++ {
		exportedWallets, err := exportWalletsForTesting(repo, password, testDir)
		if err != nil {
			t.Fatalf("Export iteration %d failed: %v", i, err)
		}

		decryptedWallets, err := decryptWalletsForTesting(exportedWallets, password)
		if err != nil {
			t.Fatalf("Decrypt iteration %d failed: %v", i, err)
		}

		if len(decryptedWallets) != 1 {
			t.Fatalf("Iteration %d: Expected 1 wallet, got %d", i, len(decryptedWallets))
		}

		decrypted := decryptedWallets[0]
		if decrypted.Address != testWallet.Address {
			t.Errorf("Iteration %d: Address mismatch", i)
		}
		if decrypted.PrivateKey != testWallet.PrivateKey {
			t.Errorf("Iteration %d: PrivateKey mismatch", i)
		}
		if decrypted.Mnemonic != testWallet.Mnemonic {
			t.Errorf("Iteration %d: Mnemonic mismatch", i)
		}
	}
}

// TestSecurityInvalidPassword ensures invalid passwords are rejected
func TestSecurityInvalidPassword(t *testing.T) {
	testWallet := &wallets.Wallet{
		Address:    "0x1234567890123456789012345678901234567890",
		PrivateKey: "secret-private-key-123",
		Mnemonic:   "secret mnemonic phrase",
	}

	repo := repository.NewInMemoryRepository().(*repository.InMemoryRepository)
	if err := repo.Insert(testWallet); err != nil {
		t.Fatalf("Failed to insert wallet: %v", err)
	}

	correctPassword := "correct-password"
	testDir := "test_output_e2e"
	defer os.RemoveAll(testDir)

	exportedWallets, err := exportWalletsForTesting(repo, correctPassword, testDir)
	if err != nil {
		t.Fatalf("Failed to export: %v", err)
	}

	// Test various invalid passwords
	invalidPasswords := []string{
		"wrong-password",
		"",
		"correct-password ",
		"Correct-Password",
		"correct-password123",
		"a",
		strings.Repeat("x", 1000),
	}

	for _, invalidPassword := range invalidPasswords {
		_, err := decryptWalletsForTesting(exportedWallets, invalidPassword)
		if err == nil {
			t.Errorf("Decryption with invalid password '%s' should have failed", invalidPassword)
		}
	}
}

// TestSecurityEncryptedDataNotLeaked ensures encrypted data doesn't reveal original
func TestSecurityEncryptedDataNotLeaked(t *testing.T) {
	testWallet := &wallets.Wallet{
		Address:    "0x1234567890123456789012345678901234567890",
		PrivateKey: "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
		Mnemonic:   "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12",
	}

	repo := repository.NewInMemoryRepository().(*repository.InMemoryRepository)
	if err := repo.Insert(testWallet); err != nil {
		t.Fatalf("Failed to insert wallet: %v", err)
	}

	password := "test-password"
	testDir := "test_output_e2e"
	defer os.RemoveAll(testDir)

	exportedWallets, err := exportWalletsForTesting(repo, password, testDir)
	if err != nil {
		t.Fatalf("Failed to export: %v", err)
	}

	// Verify encrypted data doesn't contain original plaintext
	encryptedPK := exportedWallets[0].PrivateKey
	encryptedMnemonic := exportedWallets[0].Mnemonic

	if strings.Contains(encryptedPK, testWallet.PrivateKey) {
		t.Error("Encrypted private key should not contain original plaintext")
	}
	if strings.Contains(encryptedMnemonic, testWallet.Mnemonic) {
		t.Error("Encrypted mnemonic should not contain original plaintext")
	}
	if strings.Contains(encryptedPK, testWallet.Mnemonic) {
		t.Error("Encrypted private key should not contain mnemonic")
	}
	if strings.Contains(encryptedMnemonic, testWallet.PrivateKey) {
		t.Error("Encrypted mnemonic should not contain private key")
	}
}

// Helper functions (same as in stdout_test.go but accessible from main package)
func exportWalletsForTesting(repo *repository.InMemoryRepository, password, outputDir string) ([]repository.EncryptedWallet, error) {
	if len(repo.Result()) == 0 {
		return nil, nil
	}

	encryptedWallets := make([]repository.EncryptedWallet, 0)
	for _, wallet := range repo.Result() {
		encWallet := repository.EncryptedWallet{
			Address:       wallet.Address,
			HDPath:        wallet.HDPath,
			Bits:          wallet.Bits,
			CreatedAt:     wallet.CreatedAt,
			UpdatedAt:     wallet.UpdatedAt,
			HasPrivateKey: wallet.PrivateKey != "",
			HasMnemonic:   wallet.Mnemonic != "",
		}

		if wallet.PrivateKey != "" {
			encryptedPK, err := encryption.Encrypt(wallet.PrivateKey, password)
			if err != nil {
				return nil, err
			}
			encWallet.PrivateKey = encryptedPK
		}

		if wallet.Mnemonic != "" {
			encryptedMnemonic, err := encryption.Encrypt(wallet.Mnemonic, password)
			if err != nil {
				return nil, err
			}
			encWallet.Mnemonic = encryptedMnemonic
		}

		encryptedWallets = append(encryptedWallets, encWallet)
	}

	jsonData, err := json.MarshalIndent(encryptedWallets, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return nil, err
	}

	filename := filepath.Join(outputDir, "test_wallets.encrypted.json")
	if err := os.WriteFile(filename, jsonData, 0600); err != nil {
		return nil, err
	}

	return encryptedWallets, nil
}

func decryptWalletsForTesting(encryptedWallets []repository.EncryptedWallet, password string) ([]*wallets.Wallet, error) {
	decryptedWallets := make([]*wallets.Wallet, 0, len(encryptedWallets))

	for _, encWallet := range encryptedWallets {
		wallet := &wallets.Wallet{
			Address: encWallet.Address,
			HDPath:  encWallet.HDPath,
			Bits:    encWallet.Bits,
		}
		wallet.CreatedAt = encWallet.CreatedAt
		wallet.UpdatedAt = encWallet.UpdatedAt

		if encWallet.PrivateKey != "" {
			decryptedPK, err := encryption.Decrypt(encWallet.PrivateKey, password)
			if err != nil {
				return nil, err
			}
			wallet.PrivateKey = decryptedPK
		}

		if encWallet.Mnemonic != "" {
			decryptedMnemonic, err := encryption.Decrypt(encWallet.Mnemonic, password)
			if err != nil {
				return nil, err
			}
			wallet.Mnemonic = decryptedMnemonic
		}

		decryptedWallets = append(decryptedWallets, wallet)
	}

	return decryptedWallets, nil
}
