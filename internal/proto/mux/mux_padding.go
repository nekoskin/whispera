package mux

import (
	crand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"sync"
	"time"
)

var (
	smallPaddingPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 256)
		},
	}

	mediumPaddingPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 1024)
		},
	}

	resultBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 4096)
		},
	}
)

type MuxPaddingConfig struct {
	Enabled bool
	MinSize int
	MaxSize int
}

func DefaultMuxPaddingConfig() *MuxPaddingConfig {
	return &MuxPaddingConfig{
		Enabled: true,
		MinSize: 0,
		MaxSize: 0,
	}
}

type MuxPadding struct {
	config *MuxPaddingConfig
	mu     sync.RWMutex
}

func NewMuxPadding(config *MuxPaddingConfig) *MuxPadding {
	if config == nil {
		config = DefaultMuxPaddingConfig()
	}
	return &MuxPadding{
		config: config,
	}
}

func (mp *MuxPadding) SetConfig(config *MuxPaddingConfig) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.config = config
}

func (mp *MuxPadding) GetConfig() *MuxPaddingConfig {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.config
}

func (mp *MuxPadding) ApplyPadding(data []byte) []byte {
	mp.mu.RLock()
	config := mp.config
	mp.mu.RUnlock()

	if !config.Enabled || config.MinSize == 0 && config.MaxSize == 0 {
		return data
	}

	padSize := mp.calculatePaddingSize(len(data))
	if padSize <= 0 {
		return data
	}

	padding := mp.generatePadding(padSize)

	realLen := uint16(len(data))
	totalSize := 2 + len(data) + len(padding)

	var result []byte
	if totalSize <= 512 {
		var stackBuf [512]byte
		result = stackBuf[:totalSize]
	} else if totalSize <= 4096 {
		result = resultBufferPool.Get().([]byte)
		if cap(result) < totalSize {
			result = make([]byte, totalSize)
		} else {
			result = result[:totalSize]
		}
	} else {
		result = make([]byte, totalSize)
	}

	result[0] = byte(realLen >> 8)
	result[1] = byte(realLen & 0xFF)
	copy(result[2:], data)
	copy(result[2+len(data):], padding)

	if totalSize <= 512 {
		resultCopy := make([]byte, totalSize)
		copy(resultCopy, result)
		return resultCopy
	}

	return result
}

func (mp *MuxPadding) RemovePadding(data []byte) []byte {
	if len(data) < 2 {
		return data
	}

	realLen := int(binary.BigEndian.Uint16(data[0:2]))

	if realLen <= 0 || realLen > len(data)-2 {
		return data
	}

	return data[2 : 2+realLen]
}

func (mp *MuxPadding) HasPadding(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	realLen := int(binary.BigEndian.Uint16(data[0:2]))
	return realLen > 0 && realLen < len(data)-2
}

func (mp *MuxPadding) calculatePaddingSize(dataSize int) int {
	mp.mu.RLock()
	config := mp.config
	mp.mu.RUnlock()

	if !config.Enabled {
		return 0
	}

	minSize := config.MinSize
	maxSize := config.MaxSize

	if minSize <= 0 && maxSize <= 0 {
		return 0
	}

	if minSize > maxSize {
		minSize, maxSize = maxSize, minSize
	}

	if minSize == maxSize {
		return minSize
	}

	var padSize int
	if maxSize > minSize {
		var b [4]byte
		if _, err := crand.Read(b[:]); err == nil {
			randValue := int(binary.BigEndian.Uint32(b[:])) & 0x7FFFFFFF
			padSize = minSize + (randValue % (maxSize - minSize + 1))
		} else {
			padSize = minSize + rand.Intn(maxSize-minSize+1)
		}
	} else {
		padSize = minSize
	}

	if dataSize > 1024 {
		increase := padSize / 5
		if increase > 0 {
			var b [1]byte
			if _, err := crand.Read(b[:]); err == nil {
				increase = int(b[0]) % (increase + 1)
			} else {
				increase = rand.Intn(increase + 1)
			}
			padSize += increase
		}
	}

	return padSize
}

func (mp *MuxPadding) generatePadding(size int) []byte {
	if size <= 0 {
		return nil
	}

	var padding []byte
	if size <= 256 {
		padding = smallPaddingPool.Get().([]byte)
		if cap(padding) < size {
			padding = make([]byte, size)
		} else {
			padding = padding[:size]
		}
	} else if size <= 1024 {
		padding = mediumPaddingPool.Get().([]byte)
		if cap(padding) < size {
			padding = make([]byte, size)
		} else {
			padding = padding[:size]
		}
	} else {
		padding = make([]byte, size)
	}

	if _, err := crand.Read(padding); err != nil {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		for i := range padding {
			padding[i] = byte(r.Intn(256))
		}
	}

	return padding
}

func (mp *MuxPadding) ApplyStreamPadding(streamID uint16, priority StreamPriority, data []byte) []byte {
	mp.mu.RLock()
	config := mp.config
	mp.mu.RUnlock()

	if !config.Enabled {
		return data
	}

	if priority == PriorityCritical || priority == PriorityHigh {
		originalMin := config.MinSize
		originalMax := config.MaxSize

		config.MinSize = originalMin / 2
		config.MaxSize = originalMax / 2
		if config.MinSize < 0 {
			config.MinSize = 0
		}
		if config.MaxSize < 0 {
			config.MaxSize = 0
		}

		result := mp.ApplyPadding(data)

		config.MinSize = originalMin
		config.MaxSize = originalMax

		return result
	}

	return mp.ApplyPadding(data)
}

func (mp *MuxPadding) GetPaddingStats() map[string]interface{} {
	mp.mu.RLock()
	config := mp.config
	mp.mu.RUnlock()

	return map[string]interface{}{
		"enabled":  config.Enabled,
		"min_size": config.MinSize,
		"max_size": config.MaxSize,
	}
}
