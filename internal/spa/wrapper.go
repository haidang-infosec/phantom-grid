package spa

import "github.com/cilium/ebpf"

// MapWrapper wraps ebpf.Map to implement the specific Lookup signature
type MapWrapper struct {
	Map *ebpf.Map
}

// Lookup implements the specific Lookup signature required by SPAStatsProvider
func (w *MapWrapper) Lookup(key uint32, value *uint64) error {
	return w.Map.Lookup(key, value)
}

// PhantomObjectsWrapper wraps PhantomObjects to implement SPAStatsProvider
// This is a workaround since PhantomObjects is generated in cmd/agent
type PhantomObjectsWrapper struct {
	SpaAuthSuccessMap *MapWrapper
	SpaAuthFailedMap  *MapWrapper
}

// GetSpaAuthSuccess returns the SPA auth success map
func (w *PhantomObjectsWrapper) GetSpaAuthSuccess() interface{ Lookup(key uint32, value *uint64) error } {
	return w.SpaAuthSuccessMap
}

// GetSpaAuthFailed returns the SPA auth failed map
func (w *PhantomObjectsWrapper) GetSpaAuthFailed() interface{ Lookup(key uint32, value *uint64) error } {
	return w.SpaAuthFailedMap
}

// NewWrapper creates a wrapper for PhantomObjects
func NewWrapper(successMap, failedMap *ebpf.Map) SPAStatsProvider {
	return &PhantomObjectsWrapper{
		SpaAuthSuccessMap: &MapWrapper{Map: successMap},
		SpaAuthFailedMap:  &MapWrapper{Map: failedMap},
	}
}

