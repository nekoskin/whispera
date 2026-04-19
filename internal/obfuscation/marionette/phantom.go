package marionette

func (m *Marionette) SetPhantomKey(key string) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	m.PhantomKey = key
}
