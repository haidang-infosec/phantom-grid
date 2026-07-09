package webdash

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Role constants
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// User represents an authenticated user.
type User struct {
	Username string `json:"username"`
	Password string `json:"password"` // SHA-256 hashed
	Role     string `json:"role"`
}

// AuthManager handles user authentication, authorization and sessions.
type AuthManager struct {
	mu          sync.RWMutex
	users       map[string]User // username -> User
	sessions    map[string]Session // token -> Session
	usersFile   string
}

// Session represents an active login session.
type Session struct {
	Username  string
	ExpiresAt time.Time
}

// NewAuthManager initializes a new authentication manager and loads users.
func NewAuthManager(usersFile string) *AuthManager {
	am := &AuthManager{
		users:     make(map[string]User),
		sessions:  make(map[string]Session),
		usersFile: usersFile,
	}

	am.loadUsers()

	// If no admin user exists, create default admin:admin
	if _, ok := am.users["admin"]; !ok {
		am.users["admin"] = User{
			Username: "admin",
			Password: HashPassword("admin"),
			Role:     RoleAdmin,
		}
		am.saveUsers()
	}

	// Session cleanup routine
	go am.cleanupSessions()

	return am
}

func (am *AuthManager) loadUsers() {
	// Not locking here to prevent deadlocks during initialization
	data, err := os.ReadFile(am.usersFile)
	if err != nil {
		return
	}
	
	var userList []User
	if err := json.Unmarshal(data, &userList); err != nil {
		return
	}

	for _, u := range userList {
		am.users[u.Username] = u
	}
}

func (am *AuthManager) saveUsers() {
	// Not locking here to avoid deadlock, caller must hold lock
	var userList []User
	for _, u := range am.users {
		userList = append(userList, u)
	}
	
	data, err := json.MarshalIndent(userList, "", "  ")
	if err == nil {
		os.WriteFile(am.usersFile, data, 0600)
	}
}

// HashPassword hashes a password string using SHA-256 (simplified for 0 dependencies)
func HashPassword(password string) string {
	hasher := sha256.New()
	hasher.Write([]byte(password))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Authenticate checks credentials and returns a session token if valid.
func (am *AuthManager) Authenticate(username, password string) (string, error) {
	am.mu.RLock()
	user, ok := am.users[username]
	am.mu.RUnlock()

	if !ok || user.Password != HashPassword(password) {
		return "", fmt.Errorf("invalid credentials")
	}

	// Generate a secure random token
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)

	am.mu.Lock()
	am.sessions[token] = Session{
		Username:  username,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour session
	}
	am.mu.Unlock()

	return token, nil
}

// ChangePassword updates the password for a user.
func (am *AuthManager) ChangePassword(username, oldPass, newPass string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	user, ok := am.users[username]
	if !ok {
		return fmt.Errorf("user not found")
	}

	if user.Password != HashPassword(oldPass) {
		return fmt.Errorf("incorrect old password")
	}

	user.Password = HashPassword(newPass)
	am.users[username] = user
	am.saveUsers()
	return nil
}

// ValidateToken checks if a token is valid and returns the username.
func (am *AuthManager) ValidateToken(token string) (string, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	session, ok := am.sessions[token]
	if !ok {
		return "", fmt.Errorf("invalid session")
	}

	if time.Now().After(session.ExpiresAt) {
		return "", fmt.Errorf("session expired")
	}

	return session.Username, nil
}

// GetUser returns the user object.
func (am *AuthManager) GetUser(username string) (User, bool) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	u, ok := am.users[username]
	return u, ok
}

// Logout removes a session token.
func (am *AuthManager) Logout(token string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	delete(am.sessions, token)
}

func (am *AuthManager) cleanupSessions() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		am.mu.Lock()
		now := time.Now()
		for token, session := range am.sessions {
			if now.After(session.ExpiresAt) {
				delete(am.sessions, token)
			}
		}
		am.mu.Unlock()
	}
}

type contextKey string
const UserContextKey contextKey = "user"

// AuthMiddleware protects routes by requiring a valid session cookie.
func (am *AuthManager) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Public routes
		if r.URL.Path == "/login" || r.URL.Path == "/api/auth/login" || r.URL.Path == "/metrics" || strings.HasPrefix(r.URL.Path, "/api/fleet/") {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie("phantom_session")
		if err != nil {
			if isAPIRequest(r) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}

		username, err := am.ValidateToken(cookie.Value)
		if err != nil {
			if isAPIRequest(r) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}

		user, ok := am.GetUser(username)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Inject user info into request context
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func isAPIRequest(r *http.Request) bool {
	return len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api"
}
