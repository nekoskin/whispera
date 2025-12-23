package crypto

type DummyAEADState struct{}

func NewDummyAEADState() *DummyAEADState {
	return &DummyAEADState{}
}

func (d *DummyAEADState) Encrypt(seq uint32, aad, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (d *DummyAEADState) Decrypt(seq uint32, aad, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

