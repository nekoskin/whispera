package ml

import (
	"context"
	"runtime"
	"sync"
	"time"

	"whispera/internal/obfuscation/core/types"
)

type MLJob struct {
	Data      []byte
	Context   *types.UnifiedTrafficContext
	Result    chan []byte
	Error     chan error
	Timeout   time.Duration
	Timestamp time.Time
}

type MLWorkerPool struct {
	workers    int
	jobQueue   chan *MLJob
	workerPool chan chan *MLJob
	quit       chan struct{}
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

var (
	globalMLWorkerPool *MLWorkerPool
	mlPoolOnce         sync.Once
)

func GetGlobalMLWorkerPool() *MLWorkerPool {
	mlPoolOnce.Do(func() {
		workers := runtime.NumCPU() * 2
		if workers > 16 {
			workers = 16
		}
		if workers < 2 {
			workers = 2
		}

		ctx, cancel := context.WithCancel(context.Background())
		globalMLWorkerPool = &MLWorkerPool{
			workers:    workers,
			jobQueue:   make(chan *MLJob, 1000),
			workerPool: make(chan chan *MLJob, workers),
			quit:       make(chan struct{}),
			ctx:        ctx,
			cancel:     cancel,
		}
		globalMLWorkerPool.start()
	})
	return globalMLWorkerPool
}

func (p *MLWorkerPool) start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}

	go p.dispatcher()
}

func (p *MLWorkerPool) dispatcher() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.quit:
			return
		case job := <-p.jobQueue:
			if time.Since(job.Timestamp) > job.Timeout {
				select {
				case job.Result <- job.Data:
				case job.Error <- nil:
				default:
				}
				continue
			}
			select {
			case workerChan := <-p.workerPool:
				select {
				case workerChan <- job:
				default:
					go p.processJobDirectly(job)
				}
			default:
				go p.processJobDirectly(job)
			}
		}
	}
}

func (p *MLWorkerPool) worker() {
	defer p.wg.Done()

	workerChan := make(chan *MLJob, 1)

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
				p.processJob(job)
			}
		}
	}
}

func (p *MLWorkerPool) processJob(job *MLJob) {
	defer func() {
		if r := recover(); r != nil {
			select {
			case job.Error <- nil:
			default:
			}
		}
	}()

	if time.Since(job.Timestamp) > job.Timeout {
		select {
		case job.Result <- job.Data:
		case job.Error <- nil:
		default:
		}
		return
	}

	select {
	case job.Result <- job.Data:
	case job.Error <- nil:
	default:
	}
}

func (p *MLWorkerPool) processJobDirectly(job *MLJob) {
	p.processJob(job)
}

func (p *MLWorkerPool) SubmitJob(data []byte, context *types.UnifiedTrafficContext, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		return data, nil
	}

	job := &MLJob{
		Data:      data,
		Context:   context,
		Result:    make(chan []byte, 1),
		Error:     make(chan error, 1),
		Timeout:   timeout,
		Timestamp: time.Now(),
	}

	select {
	case p.jobQueue <- job:
		select {
		case result := <-job.Result:
			return result, nil
		case err := <-job.Error:
			if err != nil {
				return data, err
			}
			return data, nil
		case <-time.After(timeout):
			return data, nil
		}
	default:
		return data, nil
	}
}

func (p *MLWorkerPool) Stop() {
	close(p.quit)
	p.cancel()
	p.wg.Wait()
}

func ProcessTrafficAsync(mlSystem *UnifiedMLSystem, data []byte, context *types.UnifiedTrafficContext, timeout time.Duration) ([]byte, error) {
	if mlSystem == nil || len(data) == 0 || timeout <= 0 {
		return data, nil
	}

	resultChan := make(chan []byte, 1)
	errorChan := make(chan error, 1)

	go func() {
		result, err := mlSystem.ProcessTraffic(data, context)
		if err != nil {
			select {
			case errorChan <- err:
			default:
			}
			return
		}
		select {
		case resultChan <- result:
		default:
		}
	}()

	select {
	case result := <-resultChan:
		if len(result) > 0 {
			return result, nil
		}
		return data, nil
	case err := <-errorChan:
		if err != nil {
			return data, err
		}
		return data, nil
	case <-time.After(timeout):
		return data, nil
	}
}
