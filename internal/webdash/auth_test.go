package webdash

import (
	"os"
	"testing"
)

func TestHashPassword(t *testing.T) {
	pass := "mysecurepassword"
	hash1 := HashPassword(pass)
	hash2 := HashPassword(pass)
	
	if hash1 != hash2 {
		t.Errorf("HashPassword should be deterministic. Got different hashes for same input.")
	}
	
	if hash1 == pass {
		t.Errorf("HashPassword should not return plain text")
	}
}

func TestAuthManager_Authenticate(t *testing.T) {
	testFile := "test_users.json"
	defer os.Remove(testFile)

	am := NewAuthManager(testFile)

	// Test default admin login
	token, err := am.Authenticate("admin", "admin")
	if err != nil {
		t.Fatalf("Failed to authenticate default admin: %v", err)
	}
	if token == "" {
		t.Errorf("Expected a token, got empty string")
	}

	// Test wrong password
	_, err = am.Authenticate("admin", "wrongpass")
	if err == nil {
		t.Errorf("Expected authentication to fail with wrong password")
	}

	// Test non-existent user
	_, err = am.Authenticate("nobody", "admin")
	if err == nil {
		t.Errorf("Expected authentication to fail for non-existent user")
	}
}

func TestAuthManager_ValidateToken(t *testing.T) {
	testFile := "test_users2.json"
	defer os.Remove(testFile)

	am := NewAuthManager(testFile)
	token, _ := am.Authenticate("admin", "admin")

	// Validate valid token
	username, err := am.ValidateToken(token)
	if err != nil {
		t.Errorf("ValidateToken failed for valid token: %v", err)
	}
	if username != "admin" {
		t.Errorf("Expected username 'admin', got '%s'", username)
	}

	// Validate invalid token
	_, err = am.ValidateToken("invalid-token")
	if err == nil {
		t.Errorf("ValidateToken should fail for invalid token")
	}
}

func TestAuthManager_ChangePassword(t *testing.T) {
	testFile := "test_users3.json"
	defer os.Remove(testFile)

	am := NewAuthManager(testFile)
	
	// Change password successfully
	err := am.ChangePassword("admin", "admin", "newpass123")
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	// Verify old password no longer works
	_, err = am.Authenticate("admin", "admin")
	if err == nil {
		t.Errorf("Old password should no longer work")
	}

	// Verify new password works
	_, err = am.Authenticate("admin", "newpass123")
	if err != nil {
		t.Errorf("New password should work, but got err: %v", err)
	}

	// Change password with wrong old password
	err = am.ChangePassword("admin", "wrongpass", "anotherpass")
	if err == nil {
		t.Errorf("ChangePassword should fail with incorrect old password")
	}
}
