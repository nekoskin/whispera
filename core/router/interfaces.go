package router

import (
	"context"
	"net"
)


type Router interface {
	
	Route(ctx context.Context, req *Request) (*Response, error)

	
	RegisterRoute(route Route) error

	
	UnregisterRoute(name string) error

	
	Use(middleware ...Middleware)

	
	GetRegistry() RouteRegistry

	
	Start(ctx context.Context) error

	
	Stop(ctx context.Context) error
}


type Route interface {
	
	Name() string

	
	Pattern() string

	
	Handler() Handler

	
	Middleware() []Middleware

	
	Priority() int

	
	Match(req *Request) bool
}


type RouteRegistry interface {
	
	Register(route Route) error

	
	Unregister(name string) error

	
	Get(name string) (Route, bool)

	
	GetAll() []Route

	
	Match(req *Request) (Route, bool)

	
	Clear()
}


type RouteMatcher interface {
	
	Match(req *Request) bool

	
	Score(req *Request) int
}


type Handler interface {
	
	Handle(ctx context.Context, req *Request) (*Response, error)
}


type HandlerFunc func(ctx context.Context, req *Request) (*Response, error)


func (f HandlerFunc) Handle(ctx context.Context, req *Request) (*Response, error) {
	return f(ctx, req)
}


type Request struct {
	
	ID string

	
	Type RequestType

	
	Data []byte

	
	Metadata map[string]interface{}

	
	RemoteAddr net.Addr

	
	SessionID string

	
	Context context.Context
}


type Response struct {
	
	Data []byte

	
	Metadata map[string]interface{}

	
	Error error

	
	StatusCode int
}


type RequestType int

const (
	
	RequestTypeHandshake RequestType = iota

	
	RequestTypeData

	
	RequestTypeControl

	
	RequestTypeRekey

	
	RequestTypeKeepalive
)
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


type RouteBuilder interface {
	
	Name(name string) RouteBuilder

	
	Pattern(pattern string) RouteBuilder

	
	Handler(handler Handler) RouteBuilder

	
	Middleware(middleware ...Middleware) RouteBuilder

	
	Priority(priority int) RouteBuilder

	
	Build() (Route, error)
}
