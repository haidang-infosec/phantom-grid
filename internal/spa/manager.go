package spa

import (
	"fmt"
	"time"
)

// SPAStatsProvider interface for accessing SPA statistics
type SPAStatsProvider interface {
	GetSpaAuthSuccess() interface {
		Lookup(key uint32, value *uint64) error
	}
	GetSpaAuthFailed() interface {
		Lookup(key uint32, value *uint64) error
	}
}

// Manager manages SPA whitelist monitoring
type Manager struct {
	statsProvider     SPAStatsProvider
	logChan           chan<- string
	whitelistDuration int
}

// NewManager creates a new SPA manager
func NewManager(statsProvider SPAStatsProvider, logChan chan<- string, whitelistDuration int) *Manager {
	return &Manager{
		statsProvider:     statsProvider,
		logChan:           logChan,
		whitelistDuration: whitelistDuration,
	}
}

// Start begins monitoring SPA statistics
func (m *Manager) Start() {
	ticker := time.NewTicker(2 * time.Second)
	var lastSuccessCount uint64 = 0
	var lastFailedCount uint64 = 0

	for range ticker.C {
		var key uint32 = 0
		var successVal uint64
		if err := m.statsProvider.GetSpaAuthSuccess().Lookup(key, &successVal); err == nil {
			if successVal > lastSuccessCount {
				m.logChan <- fmt.Sprintf("[SPA] Successful authentication! (Total: %d)", successVal)
				m.logChan <- fmt.Sprintf("[SPA] IP whitelisted for %d seconds (LRU map auto-expiry)", m.whitelistDuration)
				lastSuccessCount = successVal
			}
		}

		var failedVal uint64
		if err := m.statsProvider.GetSpaAuthFailed().Lookup(key, &failedVal); err == nil {
			if failedVal > lastFailedCount {
				m.logChan <- fmt.Sprintf("[SPA] Failed authentication attempt (Total: %d)", failedVal)
				lastFailedCount = failedVal
			}
		}
	}
}
