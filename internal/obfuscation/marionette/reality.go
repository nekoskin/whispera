package marionette

func (m *Marionette) SetRealityKey(key string) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	m.RealityKey = key
}
