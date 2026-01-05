package router

import (
	"context"
	"net"
)

// Router определяет основной интерфейс для маршрутизации запросов
type Router interface {
	// Route направляет запрос к соответствующему обработчику
	Route(ctx context.Context, req *Request) (*Response, error)

	// RegisterRoute регистрирует новый маршрут
	RegisterRoute(route Route) error

	// UnregisterRoute удаляет маршрут
	UnregisterRoute(name string) error

	// Use добавляет middleware в цепочку обработки
	Use(middleware ...Middleware)

	// GetRegistry возвращает реестр маршрутов
	GetRegistry() RouteRegistry

	// Start запускает роутер
	Start(ctx context.Context) error

	// Stop останавливает роутер
	Stop(ctx context.Context) error
}

// Route представляет отдельный маршрут в системе
type Route interface {
	// Name возвращает имя маршрута
	Name() string

	// Pattern возвращает паттерн для сопоставления
	Pattern() string

	// Handler возвращает обработчик для маршрута
	Handler() Handler

	// Middleware возвращает middleware для этого маршрута
	Middleware() []Middleware

	// Priority возвращает приоритет маршрута
	Priority() int

	// Match проверяет, соответствует ли запрос этому маршруту
	Match(req *Request) bool
}

// RouteRegistry управляет коллекцией маршрутов
type RouteRegistry interface {
	// Register регистрирует новый маршрут
	Register(route Route) error

	// Unregister удаляет маршрут по имени
	Unregister(name string) error

	// Get возвращает маршрут по имени
	Get(name string) (Route, bool)

	// GetAll возвращает все маршруты
	GetAll() []Route

	// Match находит подходящий маршрут для запроса
	Match(req *Request) (Route, bool)

	// Clear очищает все маршруты
	Clear()
}

// RouteMatcher определяет интерфейс для сопоставления маршрутов
type RouteMatcher interface {
	// Match проверяет, соответствует ли запрос критериям
	Match(req *Request) bool

	// Score возвращает оценку соответствия (больше = лучше)
	Score(req *Request) int
}

// Handler обрабатывает запросы
type Handler interface {
	// Handle обрабатывает запрос и возвращает ответ
	Handle(ctx context.Context, req *Request) (*Response, error)
}

// HandlerFunc адаптер функции к интерфейсу Handler
type HandlerFunc func(ctx context.Context, req *Request) (*Response, error)

// Handle реализует интерфейс Handler
func (f HandlerFunc) Handle(ctx context.Context, req *Request) (*Response, error) {
	return f(ctx, req)
}

// Request представляет входящий запрос
type Request struct {
	// ID уникальный идентификатор запроса
	ID string

	// Type тип запроса (handshake, data, control)
	Type RequestType

	// Data полезная нагрузка
	Data []byte

	// Metadata дополнительные метаданные
	Metadata map[string]interface{}

	// RemoteAddr адрес отправителя
	RemoteAddr net.Addr

	// SessionID идентификатор сессии
	SessionID string

	// Context контекст запроса
	Context context.Context
}

// Response представляет ответ на запрос
type Response struct {
	// Data данные ответа
	Data []byte

	// Metadata метаданные ответа
	Metadata map[string]interface{}

	// Error ошибка, если есть
	Error error

	// StatusCode код статуса
	StatusCode int
}

// RequestType определяет тип запроса
type RequestType int

const (
	// RequestTypeHandshake запрос установления соединения
	RequestTypeHandshake RequestType = iota

	// RequestTypeData запрос передачи данных
	RequestTypeData

	// RequestTypeControl управляющий запрос
	RequestTypeControl

	// RequestTypeRekey запрос смены ключей
	RequestTypeRekey

	// RequestTypeKeepalive keepalive запрос
	RequestTypeKeepalive
)

// String возвращает строковое представление типа запроса
func (rt RequestType) String() string {
	switch rt {
	case RequestTypeHandshake:
		return "handshake"
	case RequestTypeData:
		return "data"
	case RequestTypeControl:
		return "control"
	case RequestTypeRekey:
		return "rekey"
	case RequestTypeKeepalive:
		return "keepalive"
	default:
		return "unknown"
	}
}

// RouteBuilder помогает строить маршруты
type RouteBuilder interface {
	// Name устанавливает имя маршрута
	Name(name string) RouteBuilder

	// Pattern устанавливает паттерн
	Pattern(pattern string) RouteBuilder

	// Handler устанавливает обработчик
	Handler(handler Handler) RouteBuilder

	// Middleware добавляет middleware
	Middleware(middleware ...Middleware) RouteBuilder

	// Priority устанавливает приоритет
	Priority(priority int) RouteBuilder

	// Build создает маршрут
	Build() (Route, error)
}
