package obfuscation

import (
	"context"
	"runtime"
	"sync"
	"time"

	"whispera/internal/obfuscation/core/types"
)

// MLJob представляет задачу для ML обработки
type MLJob struct {
	Data      []byte
	Context   *types.UnifiedTrafficContext
	Result    chan []byte
	Error     chan error
	Timeout   time.Duration
	Timestamp time.Time
}

// MLWorkerPool - пул воркеров для асинхронной ML обработки пакетов
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

// GetGlobalMLWorkerPool возвращает глобальный пул воркеров для ML обработки
func GetGlobalMLWorkerPool() *MLWorkerPool {
	mlPoolOnce.Do(func() {
		workers := runtime.NumCPU() * 2
		if workers > 16 {
			workers = 16 // Ограничиваем максимальное количество воркеров
		}
		if workers < 2 {
			workers = 2 // Минимум 2 воркера
		}
		
		ctx, cancel := context.WithCancel(context.Background())
		globalMLWorkerPool = &MLWorkerPool{
			workers:    workers,
			jobQueue:   make(chan *MLJob, 1000), // Буферизованная очередь
			workerPool: make(chan chan *MLJob, workers),
			quit:       make(chan struct{}),
			ctx:        ctx,
			cancel:     cancel,
		}
		globalMLWorkerPool.start()
	})
	return globalMLWorkerPool
}

// start запускает пул воркеров
func (p *MLWorkerPool) start() {
	// Запускаем воркеры
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	
	// Диспетчер задач
	go p.dispatcher()
}

// dispatcher распределяет задачи по воркерам
func (p *MLWorkerPool) dispatcher() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.quit:
			return
		case job := <-p.jobQueue:
			// ОПТИМИЗАЦИЯ: Проверяем таймаут до распределения
			if time.Since(job.Timestamp) > job.Timeout {
				select {
				case job.Result <- job.Data:
				case job.Error <- nil:
				default:
				}
				continue
			}
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
func (p *MLWorkerPool) worker() {
	defer p.wg.Done()
	
	workerChan := make(chan *MLJob, 1)
	
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

// processJob обрабатывает задачу ML
func (p *MLWorkerPool) processJob(job *MLJob) {
	defer func() {
		if r := recover(); r != nil {
			select {
			case job.Error <- nil:
			default:
			}
		}
	}()
	
	// Проверяем таймаут
	if time.Since(job.Timestamp) > job.Timeout {
		select {
		case job.Result <- job.Data:
		case job.Error <- nil:
		default:
		}
		return
	}
	
	// Обрабатываем задачу (здесь будет вызов ML системы)
	// Это будет заполнено при использовании
	select {
	case job.Result <- job.Data:
	case job.Error <- nil:
	default:
	}
}

// processJobDirectly обрабатывает задачу напрямую (когда пул переполнен)
func (p *MLWorkerPool) processJobDirectly(job *MLJob) {
	p.processJob(job)
}

// SubmitJob отправляет задачу в пул воркеров
// ОПТИМИЗАЦИЯ: Упрощена логика - если очередь переполнена, сразу возвращаем исходные данные
func (p *MLWorkerPool) SubmitJob(data []byte, context *types.UnifiedTrafficContext, timeout time.Duration) ([]byte, error) {
	// ОПТИМИЗАЦИЯ: Проверяем таймаут до создания задачи
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
	
	// Пытаемся отправить задачу в очередь
	select {
	case p.jobQueue <- job:
		// Задача отправлена, ждем результат с таймаутом
		select {
		case result := <-job.Result:
			return result, nil
		case err := <-job.Error:
			if err != nil {
				return data, err
			}
			return data, nil
		case <-time.After(timeout):
			// Таймаут - возвращаем исходные данные
			return data, nil
		}
	default:
		// ОПТИМИЗАЦИЯ: Очередь переполнена, возвращаем исходные данные без блокировки
		return data, nil
	}
}

// Stop останавливает пул воркеров
func (p *MLWorkerPool) Stop() {
	close(p.quit)
	p.cancel()
	p.wg.Wait()
}

// ProcessTrafficAsync обрабатывает трафик асинхронно через worker pool
// ОПТИМИЗАЦИЯ: Упрощена логика, убрано дублирование кода
func ProcessTrafficAsync(mlSystem *UnifiedMLSystem, data []byte, context *types.UnifiedTrafficContext, timeout time.Duration) ([]byte, error) {
	if mlSystem == nil || len(data) == 0 || timeout <= 0 {
		return data, nil
	}
	
	// ОПТИМИЗАЦИЯ: Используем более эффективный подход - обрабатываем напрямую с таймаутом
	// Worker pool используется для других целей, здесь нужна быстрая обработка
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
	
	// Ждем результат с таймаутом
	select {
	case result := <-resultChan:
		if result != nil && len(result) > 0 {
			return result, nil
		}
		return data, nil
	case err := <-errorChan:
		if err != nil {
			return data, err
		}
		return data, nil
	case <-time.After(timeout):
		// Таймаут - возвращаем исходные данные
		return data, nil
	}
}

