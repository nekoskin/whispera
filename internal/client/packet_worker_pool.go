package client

import (
	"context"
	"runtime"
	"sync"
)

// PacketJob представляет задачу обработки пакета
type PacketJob struct {
	Data      []byte
	ProcessFn func([]byte) error
	Error     chan error
}

// PacketWorkerPool - пул воркеров для асинхронной обработки пакетов
type PacketWorkerPool struct {
	workers    int
	jobQueue   chan *PacketJob
	workerPool chan chan *PacketJob
	quit       chan struct{}
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

var (
	globalPacketWorkerPool *PacketWorkerPool
	packetPoolOnce         sync.Once
)

// GetGlobalPacketWorkerPool возвращает глобальный пул воркеров для обработки пакетов
func GetGlobalPacketWorkerPool() *PacketWorkerPool {
	packetPoolOnce.Do(func() {
		workers := runtime.NumCPU()
		// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Увеличено для высокой пропускной способности
		if workers > 64 {
			workers = 64
		}
		if workers < 8 {
			workers = 8 // Увеличено минимум для лучшей параллельности
		}
		
		ctx, cancel := context.WithCancel(context.Background())
		globalPacketWorkerPool = &PacketWorkerPool{
			workers:    workers,
			jobQueue:   make(chan *PacketJob, 16384), // КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Увеличено до 16384 для высокой пропускной способности
			workerPool: make(chan chan *PacketJob, workers),
			quit:       make(chan struct{}),
			ctx:        ctx,
			cancel:     cancel,
		}
		globalPacketWorkerPool.start()
	})
	return globalPacketWorkerPool
}

// start запускает пул воркеров
func (p *PacketWorkerPool) start() {
	// Запускаем воркеры
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	
	// Диспетчер задач
	go p.dispatcher()
}

// dispatcher распределяет задачи по воркерам
func (p *PacketWorkerPool) dispatcher() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.quit:
			return
		case job := <-p.jobQueue:
			// Выбираем свободного воркера
			select {
			case workerChan := <-p.workerPool:
				select {
				case workerChan <- job:
				default:
					// Воркер занят, обрабатываем напрямую
					go p.processJobDirectly(job)
				}
			default:
				// Нет свободных воркеров, обрабатываем напрямую
				go p.processJobDirectly(job)
			}
		}
	}
}

// worker обрабатывает задачи из очереди
func (p *PacketWorkerPool) worker() {
	defer p.wg.Done()
	
	workerChan := make(chan *PacketJob, 1)
	
	for {
		// Регистрируем воркера в пуле
		select {
		case <-p.ctx.Done():
			return
		case <-p.quit:
			return
		case p.workerPool <- workerChan:
			// Воркер готов к работе
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

// processJob обрабатывает задачу
func (p *PacketWorkerPool) processJob(job *PacketJob) {
	defer func() {
		if r := recover(); r != nil {
			select {
			case job.Error <- nil:
			default:
			}
		}
	}()
	
	// Обрабатываем задачу
	if job.ProcessFn != nil {
		err := job.ProcessFn(job.Data)
		select {
		case job.Error <- err:
		default:
		}
	}
}

// processJobDirectly обрабатывает задачу напрямую (когда пул переполнен)
func (p *PacketWorkerPool) processJobDirectly(job *PacketJob) {
	p.processJob(job)
}

// SubmitJob отправляет задачу в пул воркеров
func (p *PacketWorkerPool) SubmitJob(data []byte, processFn func([]byte) error) error {
	job := &PacketJob{
		Data:      data,
		ProcessFn: processFn,
		Error:     make(chan error, 1),
	}
	
	// Пытаемся отправить задачу в очередь
	select {
	case p.jobQueue <- job:
		// Задача отправлена, ждем результат
		select {
		case err := <-job.Error:
			return err
		}
	default:
		// ОПТИМИЗАЦИЯ: Очередь переполнена, обрабатываем напрямую
		return processFn(data)
	}
}

// Stop останавливает пул воркеров
func (p *PacketWorkerPool) Stop() {
	close(p.quit)
	p.cancel()
	p.wg.Wait()
}

