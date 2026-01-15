package marionette

// SetRealityKey sets the REALITY public key to enable Phantom bypass mode
func (m *Marionette) SetRealityKey(key string) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	m.RealityKey = key
}
