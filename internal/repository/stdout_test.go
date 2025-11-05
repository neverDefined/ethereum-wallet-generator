package repository

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/planxnx/ethereum-wallet-generator/internal/encryption"
	"github.com/planxnx/ethereum-wallet-generator/wallets"
	"gorm.io/gorm"
)

// TestExportAndDecrypt tests the full encryption/decryption flow
func TestExportAndDecrypt(t *testing.T) {
	// Create test wallets
	testWallets := []*wallets.Wallet{
		{
			Address:    "0x1234567890123456789012345678901234567890",
			PrivateKey: "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
			Mnemonic:   "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12",
			HDPath:     "m/44'/60'/0'/0",
			Bits:       128,
			Model:      gorm.Model{CreatedAt: time.Now(), UpdatedAt: time.Now()},
		},
		{
			Address:    "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
			PrivateKey: "f1e2d3c4b5a6789012345678901234567890abcdef1234567890abcdef123456",
			Mnemonic:   "",
			HDPath:     "",
			Bits:       0,
			Model:      gorm.Model{CreatedAt: time.Now(), UpdatedAt: time.Now()},
		},
	}

	// Create repository and add wallets
	repo := NewInMemoryRepository().(*InMemoryRepository)
	for _, wallet := range testWallets {
		if err := repo.Insert(wallet); err != nil {
			t.Fatalf("Failed to insert wallet: %v", err)
		}
	}

	// Test export with password
	password := "test-password-123"
	testDir := filepath.Join("test_output")
	originalOutputDir := "output"

	// Temporarily change output directory for testing
	defer func() {
		os.RemoveAll(testDir)
	}()

	// Create a testable export function
	exportedWallets, err := exportWalletsForTesting(repo, password, testDir)
	if err != nil {
		t.Fatalf("Failed to export wallets: %v", err)
	}

	// Verify exported structure
	if len(exportedWallets) != 2 {
		t.Fatalf("Expected 2 wallets, got %d", len(exportedWallets))
	}

	// Verify addresses are in plain text
	if exportedWallets[0].Address != testWallets[0].Address {
		t.Errorf("Address mismatch: expected %s, got %s", testWallets[0].Address, exportedWallets[0].Address)
	}

	// Verify private keys are encrypted (not equal to original)
	if exportedWallets[0].PrivateKey == testWallets[0].PrivateKey {
		t.Error("Private key should be encrypted, but matches original")
	}

	// Verify encrypted private key is not empty
	if exportedWallets[0].PrivateKey == "" {
		t.Error("Encrypted private key should not be empty")
	}

	// Verify flags are set correctly
	if !exportedWallets[0].HasPrivateKey {
		t.Error("HasPrivateKey should be true")
	}
	if !exportedWallets[0].HasMnemonic {
		t.Error("HasMnemonic should be true")
	}
	if exportedWallets[1].HasMnemonic {
		t.Error("Second wallet should not have mnemonic")
	}

	// Test decryption
	decryptedWallets, err := decryptWalletsForTesting(exportedWallets, password)
	if err != nil {
		t.Fatalf("Failed to decrypt wallets: %v", err)
	}

	// Verify decrypted data matches original
	if len(decryptedWallets) != len(testWallets) {
		t.Fatalf("Decrypted wallet count mismatch: expected %d, got %d", len(testWallets), len(decryptedWallets))
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
		if decrypted.HDPath != original.HDPath {
			t.Errorf("Wallet %d: HDPath mismatch", i)
		}
		if decrypted.Bits != original.Bits {
			t.Errorf("Wallet %d: Bits mismatch", i)
		}
	}

	// Clean up
	_ = originalOutputDir
}

// TestWrongPasswordDecryption ensures wrong password fails
func TestWrongPasswordDecryption(t *testing.T) {
	testWallet := &wallets.Wallet{
		Address:    "0x1234567890123456789012345678901234567890",
		PrivateKey: "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
		Mnemonic:   "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12",
		HDPath:     "m/44'/60'/0'/0",
		Bits:       128,
	}

	repo := NewInMemoryRepository().(*InMemoryRepository)
	if err := repo.Insert(testWallet); err != nil {
		t.Fatalf("Failed to insert wallet: %v", err)
	}

	// Export with correct password
	correctPassword := "correct-password"
	testDir := "test_output"
	exportedWallets, err := exportWalletsForTesting(repo, correctPassword, testDir)
	if err != nil {
		t.Fatalf("Failed to export: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Try to decrypt with wrong password
	wrongPassword := "wrong-password"
	_, err = decryptWalletsForTesting(exportedWallets, wrongPassword)
	if err == nil {
		t.Fatal("Decryption with wrong password should fail")
	}

	// Verify error message indicates decryption failure
	if !strings.Contains(err.Error(), "decryption failed") && !strings.Contains(err.Error(), "invalid password") {
		t.Errorf("Expected decryption error, got: %v", err)
	}
}

// TestTamperedDataDetection ensures tampered encrypted data is detected
func TestTamperedDataDetection(t *testing.T) {
	testWallet := &wallets.Wallet{
		Address:    "0x1234567890123456789012345678901234567890",
		PrivateKey: "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
		Mnemonic:   "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12",
	}

	repo := NewInMemoryRepository().(*InMemoryRepository)
	if err := repo.Insert(testWallet); err != nil {
		t.Fatalf("Failed to insert wallet: %v", err)
	}

	password := "test-password"
	testDir := "test_output"
	exportedWallets, err := exportWalletsForTesting(repo, password, testDir)
	if err != nil {
		t.Fatalf("Failed to export: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Tamper with encrypted data
	exportedWallets[0].PrivateKey = "tampered-encrypted-data"

	// Try to decrypt - should fail
	_, err = decryptWalletsForTesting(exportedWallets, password)
	if err == nil {
		t.Fatal("Decryption of tampered data should fail")
	}
}

// TestEmptyWalletExport ensures empty repository doesn't crash
func TestEmptyWalletExport(t *testing.T) {
	repo := NewInMemoryRepository().(*InMemoryRepository)
	testDir := "test_output"
	defer os.RemoveAll(testDir)

	// Should not error on empty repository
	exportedWallets, err := exportWalletsForTesting(repo, "password", testDir)
	if err != nil {
		t.Fatalf("Empty export should not error: %v", err)
	}
	if len(exportedWallets) != 0 {
		t.Errorf("Expected 0 wallets, got %d", len(exportedWallets))
	}
}

// TestWalletWithOnlyAddress ensures wallets without private key/mnemonic work
func TestWalletWithOnlyAddress(t *testing.T) {
	testWallet := &wallets.Wallet{
		Address:    "0x1234567890123456789012345678901234567890",
		PrivateKey: "",
		Mnemonic:   "",
		HDPath:     "m/44'/60'/0'/0",
		Bits:       128,
	}

	repo := NewInMemoryRepository().(*InMemoryRepository)
	if err := repo.Insert(testWallet); err != nil {
		t.Fatalf("Failed to insert wallet: %v", err)
	}

	password := "test-password"
	testDir := "test_output"
	exportedWallets, err := exportWalletsForTesting(repo, password, testDir)
	if err != nil {
		t.Fatalf("Failed to export: %v", err)
	}
	defer os.RemoveAll(testDir)

	if len(exportedWallets) != 1 {
		t.Fatalf("Expected 1 wallet, got %d", len(exportedWallets))
	}

	if exportedWallets[0].HasPrivateKey {
		t.Error("Wallet should not have private key flag set")
	}
	if exportedWallets[0].HasMnemonic {
		t.Error("Wallet should not have mnemonic flag set")
	}
	if exportedWallets[0].PrivateKey != "" {
		t.Error("PrivateKey field should be empty/omitted")
	}
	if exportedWallets[0].Mnemonic != "" {
		t.Error("Mnemonic field should be empty/omitted")
	}
}

// TestAddressAlwaysVisible ensures addresses are never encrypted
func TestAddressAlwaysVisible(t *testing.T) {
	testWallet := &wallets.Wallet{
		Address:    "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
		PrivateKey: "secret-key-123",
		Mnemonic:   "secret mnemonic phrase",
	}

	repo := NewInMemoryRepository().(*InMemoryRepository)
	if err := repo.Insert(testWallet); err != nil {
		t.Fatalf("Failed to insert wallet: %v", err)
	}

	password := "test-password"
	testDir := "test_output"
	exportedWallets, err := exportWalletsForTesting(repo, password, testDir)
	if err != nil {
		t.Fatalf("Failed to export: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Address should be exactly as original (not encrypted)
	if exportedWallets[0].Address != testWallet.Address {
		t.Errorf("Address should be visible: expected %s, got %s", testWallet.Address, exportedWallets[0].Address)
	}

	// Address should not look encrypted (no base64 padding, etc.)
	if len(exportedWallets[0].Address) != len(testWallet.Address) {
		t.Error("Address length should not change")
	}
}

// TestMultipleWalletsExport tests exporting multiple wallets
func TestMultipleWalletsExport(t *testing.T) {
	repo := NewInMemoryRepository().(*InMemoryRepository)
	numWallets := 10

	for i := 0; i < numWallets; i++ {
		wallet := &wallets.Wallet{
			Address:    "0x" + strings.Repeat("a", 40),
			PrivateKey: "private-key-" + string(rune(i+'0')),
			Mnemonic:   "mnemonic phrase " + string(rune(i+'0')),
		}
		if err := repo.Insert(wallet); err != nil {
			t.Fatalf("Failed to insert wallet %d: %v", i, err)
		}
	}

	password := "test-password"
	testDir := "test_output"
	exportedWallets, err := exportWalletsForTesting(repo, password, testDir)
	if err != nil {
		t.Fatalf("Failed to export: %v", err)
	}
	defer os.RemoveAll(testDir)

	if len(exportedWallets) != numWallets {
		t.Fatalf("Expected %d wallets, got %d", numWallets, len(exportedWallets))
	}

	// Decrypt and verify all
	decryptedWallets, err := decryptWalletsForTesting(exportedWallets, password)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if len(decryptedWallets) != numWallets {
		t.Fatalf("Expected %d decrypted wallets, got %d", numWallets, len(decryptedWallets))
	}
}

// Helper function to export wallets for testing (avoids stdin interaction)
func exportWalletsForTesting(repo *InMemoryRepository, password, outputDir string) ([]EncryptedWallet, error) {
	if len(repo.wallets) == 0 {
		return nil, nil
	}

	encryptedWallets := make([]EncryptedWallet, 0, len(repo.wallets))
	for _, wallet := range repo.wallets {
		encWallet := EncryptedWallet{
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

	// Write to test file
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

// Helper function to decrypt wallets for testing
func decryptWalletsForTesting(encryptedWallets []EncryptedWallet, password string) ([]*wallets.Wallet, error) {
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
