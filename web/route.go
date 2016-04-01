package web

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	//"net/url"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Applet struct {
	initFn reflect.Value
	routes Routes
	Config *Config
	Logger *log.Logger
}

func (this *Applet) Url(name string, args ...interface{}) *URL {
	var link = &URL{}
	if route, ok := this.routes[strings.ToUpper(name)]; ok {
		reg := regexp.MustCompile(`\([^()]*\)`)
		str := reg.ReplaceAllString(route.r, "%s")
		if str == route.r {
			link.Path = str
		} else {
			for idx, arg := range args {
				args[idx] = fmt.Sprint(arg)
			}
			link.Path = fmt.Sprintf(str, args...)
		}
	} else {
		//没找到url
		this.Logger.Println("没找到url")
	}
	return link
}

type Config struct {
	Debug    bool
	AppPath  string
	themeDir string
	tempMap  map[string][]byte
	FuncMap  template.FuncMap
	//	StaticDir    string
	Addr         string
	Port         int
	CookieSecret string
	RecoverPanic bool
	Profiler     bool
}
type Routes map[string]*Route

func (this *Applet) Init(themePath string) *Applet {
	if this.Logger == nil {
		this.Logger = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	}
	this.Logger.SetFlags(log.Lshortfile | log.LstdFlags)
	this.Config = &Config{
		RecoverPanic: true,
		themeDir:     themePath,
		tempMap:      map[string][]byte{},
		FuncMap:      map[string]interface{}{},
	}
	this.routes = make(Routes)
	this.initFn = reflect.ValueOf(func(ctx *Context) *Context {
		return ctx
	})
	return this
}

func (this *Applet) InitFn(fn interface{}) *Applet {
	switch fn.(type) {
	case reflect.Value:
		this.initFn = fn.(reflect.Value)
	default:
		fv := reflect.ValueOf(fn)
		this.initFn = fv
	}
	return this
}

func (this *Applet) Run() {
	if !this.Config.Debug {
		this.Config.tempMap = loadTempMap(this.Config.themeDir)
	}

	mux := http.NewServeMux()
	mux.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
	mux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
	mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	mux.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
	mux.Handle("/", this)
	addr := fmt.Sprintf(":%d", this.Config.Port)
	this.Logger.Printf("meepo web server %s\n", addr)

	l, err := net.Listen("tcp", addr)
	if err != nil {
		this.Logger.Fatal("ListenAndServe:", err)
	}

	err = http.Serve(l, mux)
	l.Close()
}

func (this *Applet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	this.RouteHandler(w, r)
}

func (this *Applet) Route(ident, patten string) *Route {
	ident = strings.ToUpper(ident)
	route, ok := this.routes[ident]
	if !ok {
		this.routes[ident] = new(Route).Init(ident, patten)
		return this.routes[ident]
	} else {
		return route
	}
}

type Route struct {
	Ident     string
	r         string
	cr        *regexp.Regexp
	initFn    reflect.Value
	WSHander  http.Handler
	GetFuncs  []reflect.Value
	PostFuncs []reflect.Value
	PutFuncs  []reflect.Value
	DelFuncs  []reflect.Value
}

func (this *Route) Init(ident, r string) *Route {
	this.Ident = ident
	cr, err := regexp.Compile(r)
	if err != nil {
		return this
	}
	this.r = r
	this.cr = cr
	return this
}

func (this *Route) InitFn(fn interface{}) *Route {
	switch fn.(type) {
	case reflect.Value:
		this.initFn = fn.(reflect.Value)
	default:
		fv := reflect.ValueOf(fn)
		this.initFn = fv
	}
	return this
}

func (this *Route) Get(handlers ...interface{}) *Route {
	if len(this.GetFuncs) > 0 {
		panic("double")
	}
	for _, handler := range handlers {
		switch handler.(type) {
		case reflect.Value:
			fv := handler.(reflect.Value)
			this.GetFuncs = append(this.GetFuncs, fv)
		default:
			fv := reflect.ValueOf(handler)
			this.GetFuncs = append(this.GetFuncs, fv)
		}
	}
	return this
}

func (this *Route) Post(handlers ...interface{}) *Route {
	if len(this.PostFuncs) > 0 {
		panic("double")
	}
	for _, handler := range handlers {
		switch handler.(type) {
		case reflect.Value:
			fv := handler.(reflect.Value)
			this.PostFuncs = append(this.PostFuncs, fv)
		default:
			fv := reflect.ValueOf(handler)
			this.PostFuncs = append(this.PostFuncs, fv)
		}
	}
	return this
}

func (this *Route) Put(handlers ...interface{}) *Route {
	if len(this.PutFuncs) > 0 {
		panic("double")
	}
	for _, handler := range handlers {
		switch handler.(type) {
		case reflect.Value:
			fv := handler.(reflect.Value)
			this.PutFuncs = append(this.PutFuncs, fv)
		default:
			fv := reflect.ValueOf(handler)
			this.PutFuncs = append(this.PutFuncs, fv)
		}
	}
	return this
}

func (this *Route) Delete(handlers ...interface{}) *Route {
	if len(this.DelFuncs) > 0 {
		panic("double")
	}
	for _, handler := range handlers {
		switch handler.(type) {
		case reflect.Value:
			fv := handler.(reflect.Value)
			this.DelFuncs = append(this.DelFuncs, fv)
		default:
			fv := reflect.ValueOf(handler)
			this.DelFuncs = append(this.DelFuncs, fv)
		}
	}
	return this
}

func (this *Route) WS(handler http.Handler) *Route {
	this.WSHander = handler
	return this
}

func (this *Applet) RouteHandler(w http.ResponseWriter, req *http.Request) {
	ctx := Context{isBreak: false, Request: req, Params: map[string]string{}, Applet: this, ResponseWriter: w}
	tm := time.Now().UTC()
	ctx.SetHeader("Server", "Meepo", true)
	ctx.SetHeader("Date", webTime(tm), true)

	req.ParseForm()
	if len(req.Form) > 0 {
		for k, v := range req.Form {
			ctx.Params[k] = v[0]
		}
	}

	defer this.logRequest(ctx, tm)

	for _, _route := range this.routes {
		if !_route.cr.MatchString(req.URL.Path) {
			continue
		}
		var funcs []reflect.Value
		method := strings.ToUpper(req.Method)
		switch method {
		case "GET":
			if _route.WSHander != nil {
				//todo websocket
				_route.WSHander.ServeHTTP(w, req)
				return
			}
			funcs = _route.GetFuncs
		case "POST":
			funcs = _route.PostFuncs
		default:
			fmt.Println(method)
			continue
		}

		if len(funcs) == 0 {
			continue
		}
		match := _route.cr.FindStringSubmatch(req.URL.Path)
		if len(match[0]) != len(req.URL.Path) {
			continue
		}
		var fn reflect.Value
		if _route.initFn.IsValid() {
			fn = _route.initFn
		} else {
			fn = this.initFn
		}
		page := fn.Call([]reflect.Value{reflect.ValueOf(&ctx)})[0]
		//isEnd := ctx.ResponseWriter.Header().Get("Location")
		//if len(isEnd) > 0 {
		//	this.Logger.Println(ctx.ResponseWriter.Header())
		//	this.Logger.Println("isEnd", isEnd, len(isEnd))
		//	return
		//}
		for _, _handler := range funcs {
			if ctx.isBreak {
				break
			}
			var args []reflect.Value
			handlerType := _handler.Type()
			if func(handlerType reflect.Type) bool {
				if handlerType.NumIn() == 0 {
					return false
				}
				a0 := handlerType.In(0)
				if a0.Kind() != reflect.Ptr {
					return false
				}
				if a0.Elem() == page.Type().Elem() {
					return true
				}
				return false
			}(handlerType) {
				args = append(args, page)
			}
			for _, arg := range match[1:] {
				if len(args) < handlerType.NumIn() {
					args = append(args, reflect.ValueOf(arg))
				} else {
					break
				}
			}
			//			this.Logger.Println("args", reflect.TypeOf(args), args)

			result, err := this.safelyCall(_handler, args)
			if err != nil {
				ctx.Abort(500, "Server Error")
			}
			if len(result) > 0 {
				sval := result[0]
				var content []byte
				if sval.Kind() == reflect.Bool && sval.Bool() {
					return
				} else if sval.Kind() == reflect.String {
					content = []byte(sval.String())
				} else if sval.Kind() == reflect.Slice && sval.Type().Elem().Kind() == reflect.Uint8 {
					content = sval.Interface().([]byte)
				}
				this.Logger.Println(sval.Kind())

				if len(content) > 0 {
					this.Logger.Println(len(content), string(content))
					if ctx.Request.Header.Get("Content-Type") == "" {

						ctx.SetHeader("Content-Type", "text/html; charset=utf-8", true)
					}
					fmt.Println(ctx.Request.Header.Get("Content-Type"))
					ctx.SetHeader("Content-Length", strconv.Itoa(len(content)), true)
					_, err = ctx.ResponseWriter.Write(content)
					if err != nil {
						this.Logger.Println("Error during write: ", err)
					}
					return
				}
			}
		}
		return
	}
	ctx.Abort(404, "404 Page not found")
	return
}
func (this *Applet) logRequest(ctx Context, sTime time.Time) {
	//log the request
	var logEntry bytes.Buffer
	req := ctx.Request
	requestPath := req.URL.String()

	duration := time.Now().Sub(sTime)
	var client string

	// We suppose RemoteAddr is of the form Ip:Port as specified in the Request
	// documentation at http://golang.org/pkg/net/http/#Request
	pos := strings.LastIndex(req.RemoteAddr, ":")
	if pos > 0 {
		client = req.RemoteAddr[0:pos]
	} else {
		client = req.RemoteAddr
	}

	fmt.Fprintf(&logEntry, "%s - [%s] %s - %v", client, req.Method, requestPath, duration)
	if len(ctx.Params) > 0 {
		fmt.Fprintf(&logEntry, "\n")
	}
	this.Logger.Print(logEntry.String())
}

func (this *Applet) safelyCall(function reflect.Value, args []reflect.Value) (resp []reflect.Value, e interface{}) {
	defer func() {
		if err := recover(); err != nil {
			if !this.Config.RecoverPanic {
				panic(err)
			} else {
				e = err
				resp = nil
				this.Logger.Println("Handler crashed with error", err)
				for i := 1; ; i += 1 {
					_, file, line, ok := runtime.Caller(i)
					if !ok {
						break
					}
					this.Logger.Println(file, line)
				}
			}
		}
	}()
	return function.Call(args), nil
}
