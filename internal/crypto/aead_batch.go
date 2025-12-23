package crypto

import (
	"sync"
)

// BatchAEADState - состояние для batch шифрования
type BatchAEADState struct {
	*AEADState
	batchBuffer []byte
	mu          sync.Mutex
}

// NewBatchAEADState создает новый batch AEAD state
func NewBatchAEADState(aeadState *AEADState) *BatchAEADState {
	return &BatchAEADState{
		AEADState:   aeadState,
		batchBuffer: make([]byte, 0, 65535),
	}
}

// BatchEncrypt шифрует несколько пакетов за раз (для уменьшения overhead)
// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Параллельное шифрование для высокой пропускной способности
func (b *BatchAEADState) BatchEncrypt(seq uint32, aad []byte, plaintexts [][]byte) ([][]byte, error) {
	results := make([][]byte, len(plaintexts))
	
	// Если только один пакет, используем обычное шифрование
	if len(plaintexts) == 1 {
		ct, err := b.Encrypt(seq, aad, plaintexts[0])
		if err != nil {
			return nil, err
		}
		results[0] = ct
		return results, nil
	}
	
	// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Параллельное шифрование для множественных пакетов
	var wg sync.WaitGroup
	errChan := make(chan error, len(plaintexts))
	
	for i, plaintext := range plaintexts {
		wg.Add(1)
		go func(idx int, pt []byte) {
			defer wg.Done()
			// Используем seq + idx для уникальности nonce
			ct, err := b.Encrypt(seq+uint32(idx), aad, pt)
			if err != nil {
				errChan <- err
				return
			}
			results[idx] = ct
		}(i, plaintext)
	}
	
	wg.Wait()
	close(errChan)
	
	// Проверяем ошибки
	if len(errChan) > 0 {
		return nil, <-errChan
	}
	
	return results, nil
}

// BatchDecrypt расшифровывает несколько пакетов параллельно
func (b *BatchAEADState) BatchDecrypt(seq uint32, aad []byte, ciphertexts [][]byte) ([][]byte, error) {
	results := make([][]byte, len(ciphertexts))
	
	if len(ciphertexts) == 1 {
		pt, err := b.Decrypt(seq, aad, ciphertexts[0])
		if err != nil {
			return nil, err
		}
		results[0] = pt
		return results, nil
	}
	
	var wg sync.WaitGroup
	errChan := make(chan error, len(ciphertexts))
	
	for i, ciphertext := range ciphertexts {
		wg.Add(1)
		go func(idx int, ct []byte) {
			defer wg.Done()
			pt, err := b.Decrypt(seq+uint32(idx), aad, ct)
			if err != nil {
				errChan <- err
				return
			}
			results[idx] = pt
		}(i, ciphertext)
	}
	
	wg.Wait()
	close(errChan)
	
	if len(errChan) > 0 {
		return nil, <-errChan
	}
	
	return results, nil
}

// EncryptOptimized - оптимизированное шифрование с проверкой размера
func (s *AEADState) EncryptOptimized(seq uint32, aad, plaintext []byte) ([]byte, error) {
	// Для очень маленьких пакетов используем стандартный Encrypt
	// Оптимизация может быть добавлена позже на уровне компиляции
	return s.Encrypt(seq, aad, plaintext)
}

// EncryptControl - шифрование контрольных пакетов
// Для безопасности всегда используем полное шифрование
func (s *AEADState) EncryptControl(seq uint32, aad, plaintext []byte, encrypt bool) ([]byte, error) {
	// Всегда шифруем для безопасности (encrypt параметр зарезервирован для будущего)
	_ = encrypt
	return s.Encrypt(seq, aad, plaintext)
}

// StreamAEADState - состояние для stream шифрования (как в XTLS-Vision)
type StreamAEADState struct {
	*AEADState
	streamCounter uint64
	mu            sync.Mutex
}

// NewStreamAEADState создает stream AEAD state
func NewStreamAEADState(aeadState *AEADState) *StreamAEADState {
	return &StreamAEADState{
		AEADState:    aeadState,
		streamCounter: 0,
	}
}

// ОПТИМИЗАЦИЯ: Статический AAD для stream шифрования (переиспользуем)
var streamAAD = []byte{0x01} // Stream flag

// EncryptStream шифрует stream данных (оптимизация для больших потоков)
func (s *StreamAEADState) EncryptStream(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	seq := uint32(s.streamCounter)
	s.streamCounter++
	s.mu.Unlock()
	
	// ОПТИМИЗАЦИЯ: Используем статический AAD вместо создания каждый раз
	return s.Encrypt(seq, streamAAD, plaintext)
}

