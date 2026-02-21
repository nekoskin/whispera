package crypt

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	cryptopkg "whispera/internal/crypto"
)


type DecryptJob struct {
	Seq        uint32
	AAD        []byte
	Ciphertext []byte
	AEADState  *cryptopkg.AEADState
	Result     chan []byte
	Error      chan error
	Timeout    time.Duration
}


type DecryptWorkerPool struct {
	workers       int
	jobQueue      chan *DecryptJob
	workerPool    chan chan *DecryptJob
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
	globalDecryptWorkerPool *DecryptWorkerPool
	decryptPoolOnce         sync.Once
)


func NewDecryptWorkerPool(ctx context.Context, workers int) *DecryptWorkerPool {
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
	pool := &DecryptWorkerPool{
		workers:    workers,
		jobQueue:   make(chan *DecryptJob, 262144), 
		workerPool: make(chan chan *DecryptJob, workers),
		quit:       make(chan struct{}),
		ctx:        poolCtx,
		cancel:     cancel,
	}
	pool.start()
	return pool
}


func GetGlobalDecryptWorkerPool() *DecryptWorkerPool {
	decryptPoolOnce.Do(func() {
		workers := runtime.NumCPU()
		
		if workers > 64 {
			workers = 64
		}
		if workers < 8 { 
			workers = 8
		}

		ctx, cancel := context.WithCancel(context.Background())
		globalDecryptWorkerPool = &DecryptWorkerPool{
			workers:    workers,
			jobQueue:   make(chan *DecryptJob, 262144), 
			workerPool: make(chan chan *DecryptJob, workers),
			quit:       make(chan struct{}),
			ctx:        ctx,
			cancel:     cancel,
		}
		globalDecryptWorkerPool.start()
	})
	return globalDecryptWorkerPool
}


func (p *DecryptWorkerPool) start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	go p.dispatcher()
}


func (p *DecryptWorkerPool) dispatcher() {
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


func (p *DecryptWorkerPool) worker() {
	defer p.wg.Done()
	workerChan := make(chan *DecryptJob, 1)
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
				
				plaintext, err := job.AEADState.Decrypt(job.Seq, job.AAD, job.Ciphertext)
				if err != nil {
					atomic.AddInt64(&p.jobsFailed, 1)
					select {
					case job.Error <- err:
					default:
					}
				} else {
					select {
					case job.Result <- plaintext:
					default:
					}
				}
			}
		}
	}
}


func (p *DecryptWorkerPool) DecryptAsync(seq uint32, aad, ciphertext []byte, aeadState *cryptopkg.AEADState, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = 5 * time.Millisecond 
	}

	job := &DecryptJob{
		Seq:        seq,
		AAD:        aad,
		Ciphertext: ciphertext,
		AEADState:  aeadState,
		Result:     make(chan []byte, 1),
		Error:      make(chan error, 1),
		Timeout:    timeout,
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
			return nil, ErrDecryptTimeout
		}
	default:
		
		res, err := aeadState.Decrypt(seq, aad, ciphertext)
		if err != nil {
			atomic.AddInt64(&p.jobsFailed, 1)
			return nil, err
		}
		atomic.AddInt64(&p.jobsProcessed, 1)
		return res, nil
	}
}


func (p *DecryptWorkerPool) Stop() {
	close(p.quit)
	p.cancel()
	p.wg.Wait()
}
func (p *DecryptWorkerPool) GetStats() (submitted, processed, dropped, failed int64) {
	return atomic.LoadInt64(&p.jobsSubmitted), atomic.LoadInt64(&p.jobsProcessed),
		atomic.LoadInt64(&p.jobsDropped), atomic.LoadInt64(&p.jobsFailed)
}


var ErrDecryptTimeout = &DecryptError{Message: "decrypt timeout"}


type DecryptError struct {
	Message string
}

func (e *DecryptError) Error() string {
	return e.Message
}
