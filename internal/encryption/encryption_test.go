package encryption

import (
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	plaintext := "test-secret-data-12345"
	password := "my-secure-password"

	encrypted, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if encrypted == "" {
		t.Error("Encrypted data should not be empty")
	}

	if encrypted == plaintext {
		t.Error("Encrypted data should not match plaintext")
	}

	decrypted, err := Decrypt(encrypted, password)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypted text mismatch: expected %s, got %s", plaintext, decrypted)
	}
}

func TestEncryptDecryptWrongPassword(t *testing.T) {
	plaintext := "secret-data"
	correctPassword := "correct-password"
	wrongPassword := "wrong-password"

	encrypted, err := Encrypt(plaintext, correctPassword)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	_, err = Decrypt(encrypted, wrongPassword)
	if err == nil {
		t.Fatal("Decryption with wrong password should fail")
	}
}

func TestEncryptDecryptEmptyString(t *testing.T) {
	password := "test-password"

	encrypted, err := Encrypt("", password)
	if err != nil {
		t.Fatalf("Encryption of empty string should not error: %v", err)
	}

	if encrypted != "" {
		t.Error("Encrypted empty string should be empty")
	}

	decrypted, err := Decrypt(encrypted, password)
	if err != nil {
		t.Fatalf("Decryption of empty string should not error: %v", err)
	}

	if decrypted != "" {
		t.Error("Decrypted empty string should be empty")
	}
}

func TestEncryptDifferentPasswords(t *testing.T) {
	plaintext := "same-secret-data"
	password1 := "password1"
	password2 := "password2"

	encrypted1, err := Encrypt(plaintext, password1)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	encrypted2, err := Encrypt(plaintext, password2)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Same plaintext encrypted with different passwords should produce different ciphertext
	if encrypted1 == encrypted2 {
		t.Error("Same plaintext with different passwords should produce different ciphertext")
	}

	// Each should only decrypt with its own password
	decrypted1, err := Decrypt(encrypted1, password1)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if decrypted1 != plaintext {
		t.Error("Decryption with correct password should work")
	}

	_, err = Decrypt(encrypted1, password2)
	if err == nil {
		t.Error("Decryption with wrong password should fail")
	}
}

func TestEncryptSamePasswordDifferentPlaintext(t *testing.T) {
	password := "same-password"
	plaintext1 := "secret-data-1"
	plaintext2 := "secret-data-2"

	encrypted1, err := Encrypt(plaintext1, password)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	encrypted2, err := Encrypt(plaintext2, password)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Different plaintext should produce different ciphertext (even with same password)
	if encrypted1 == encrypted2 {
		t.Error("Different plaintext should produce different ciphertext")
	}
}

func TestEncryptTamperedData(t *testing.T) {
	plaintext := "secret-data"
	password := "test-password"

	encrypted, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Tamper with encrypted data
	tampered := encrypted[:len(encrypted)-10] + "XXXXXXXXXX"

	_, err = Decrypt(tampered, password)
	if err == nil {
		t.Fatal("Decryption of tampered data should fail")
	}
}

func TestEncryptLongPlaintext(t *testing.T) {
	// Test with long mnemonic phrase
	longPlaintext := "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12 word13 word14 word15 word16 word17 word18 word19 word20 word21 word22 word23 word24"
	password := "test-password"

	encrypted, err := Encrypt(longPlaintext, password)
	if err != nil {
		t.Fatalf("Encryption of long plaintext failed: %v", err)
	}

	decrypted, err := Decrypt(encrypted, password)
	if err != nil {
		t.Fatalf("Decryption of long plaintext failed: %v", err)
	}

	if decrypted != longPlaintext {
		t.Error("Long plaintext decryption mismatch")
	}
}

func TestEncryptSpecialCharacters(t *testing.T) {
	plaintext := "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
	password := "password-with-special-chars!@#"

	encrypted, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := Decrypt(encrypted, password)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Error("Special characters not preserved")
	}
}

