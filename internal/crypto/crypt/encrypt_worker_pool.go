package crypt

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	cryptopkg "whispera/internal/crypto"
)


type EncryptJob struct {
	Seq       uint32
	AAD       []byte
	Plaintext []byte
	AEADState *cryptopkg.AEADState
	Result    chan []byte
	Error     chan error
	Timeout   time.Duration
}


type EncryptWorkerPool struct {
	workers       int
	jobQueue      chan *EncryptJob
	workerPool    chan chan *EncryptJob
	quit          chan struct{}
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	jobsSubmitted int64
	jobsProcessed int64
	jobsDropped   int64
	jobsFailed    int64
}

var (
	globalEncryptWorkerPool *EncryptWorkerPool
	encryptPoolOnce         sync.Once
)


func NewEncryptWorkerPool(ctx context.Context, workers int, state *cryptopkg.AEADState) *EncryptWorkerPool {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > 64 {
		workers = 64
	}
	if workers < 8 {
		workers = 8
	}

	poolCtx, cancel := context.WithCancel(ctx)
	pool := &EncryptWorkerPool{
		workers:    workers,
		jobQueue:   make(chan *EncryptJob, 262144), 
		workerPool: make(chan chan *EncryptJob, workers),
		quit:       make(chan struct{}),
		ctx:        poolCtx,
		cancel:     cancel,
	}
	pool.start()
	return pool
}


func GetGlobalEncryptWorkerPool() *EncryptWorkerPool {
	encryptPoolOnce.Do(func() {
		workers := runtime.NumCPU()
		
		if workers > 64 {
			workers = 64
		}
		if workers < 8 {
			workers = 8 
		}

		ctx, cancel := context.WithCancel(context.Background())
		globalEncryptWorkerPool = &EncryptWorkerPool{
			workers:    workers,
			jobQueue:   make(chan *EncryptJob, 262144), 
			workerPool: make(chan chan *EncryptJob, workers),
			quit:       make(chan struct{}),
			ctx:        ctx,
			cancel:     cancel,
		}
		globalEncryptWorkerPool.start()
	})
	return globalEncryptWorkerPool
}


func (p *EncryptWorkerPool) start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	go p.dispatcher()
}


func (p *EncryptWorkerPool) dispatcher() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.quit:
			return
		case job := <-p.jobQueue:
			select {
			case workerChan := <-p.workerPool:
				select {
				case workerChan <- job:
				default:
					
					atomic.AddInt64(&p.jobsDropped, 1)
				}
			default:
				
				atomic.AddInt64(&p.jobsDropped, 1)
			}
		}
	}
}


func (p *EncryptWorkerPool) worker() {
	defer p.wg.Done()
	workerChan := make(chan *EncryptJob, 1)
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.quit:
			return
		case p.workerPool <- workerChan: 
			select {
			case <-p.ctx.Done():
				return
			case <-p.quit:
				return
			case job := <-workerChan:
				atomic.AddInt64(&p.jobsProcessed, 1)
				
				ciphertext, err := job.AEADState.Encrypt(job.Seq, job.AAD, job.Plaintext)
				if err != nil {
					atomic.AddInt64(&p.jobsFailed, 1)
					select {
					case job.Error <- err:
					default:
					}
				} else {
					select {
					case job.Result <- ciphertext:
					default:
					}
				}
			}
		}
	}
}


func (p *EncryptWorkerPool) EncryptAsync(seq uint32, aad, plaintext []byte, aeadState *cryptopkg.AEADState, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = 50 * time.Millisecond 
	}

	job := &EncryptJob{
		Seq:       seq,
		AAD:       aad,
		Plaintext: plaintext,
		AEADState: aeadState,
		Result:    make(chan []byte, 1),
		Error:     make(chan error, 1),
		Timeout:   timeout,
	}

	atomic.AddInt64(&p.jobsSubmitted, 1)

	select {
	case p.jobQueue <- job:
		
		select {
		case result := <-job.Result:
			return result, nil
		case err := <-job.Error:
			return nil, err
		case <-time.After(timeout):
			atomic.AddInt64(&p.jobsDropped, 1)
			return nil, ErrEncryptTimeout
		}
	default:
		
		res, err := aeadState.Encrypt(seq, aad, plaintext)
		if err != nil {
			atomic.AddInt64(&p.jobsFailed, 1)
			return nil, err
		}
		atomic.AddInt64(&p.jobsProcessed, 1)
		return res, nil
	}
}


func (p *EncryptWorkerPool) Stop() {
	close(p.quit)
	p.cancel()
	p.wg.Wait()
}


func (p *EncryptWorkerPool) GetStats() (submitted, processed, dropped, failed int64) {
	return atomic.LoadInt64(&p.jobsSubmitted), atomic.LoadInt64(&p.jobsProcessed),
		atomic.LoadInt64(&p.jobsDropped), atomic.LoadInt64(&p.jobsFailed)
}
var ErrEncryptTimeout = &EncryptError{Message: "encrypt timeout"}


type EncryptError struct {
	Message string
}

func (e *EncryptError) Error() string {
	return e.Message
}
