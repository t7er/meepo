package web

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type URL struct {
	url.URL
}

func (this *URL) Add(key, val string) *URL {
	if val != "" {
		vals := this.URL.Query()
		vals.Add(key, val)
		this.URL.RawQuery = vals.Encode()
	}
	return this
}

type Context struct {
	Request *http.Request
	Params  map[string]string
	Applet  *Applet
	http.ResponseWriter
}

func (this *Context) Int(key string, def int) int {
	if val, ok := this.Params[key]; ok {
		if i, e := strconv.Atoi(val); e == nil {
			return i
		}
	}
	return def
}

func (this *Context) String(key, def string) string {
	if val, ok := this.Params[key]; ok {
		return val
	}
	return def
}

func (this *Context) Write(content interface{}) {
	switch v := content.(type) {
	case int:
		this.ResponseWriter.Write([]byte(fmt.Sprintf("%d", v)))
	case []byte:
		this.ResponseWriter.Write(v)
	case string:
		this.ResponseWriter.Write([]byte(v))
	default:
		this.ResponseWriter.Write([]byte(fmt.Sprint(v)))
	}
}

func (this *Context) Url(name string, args ...interface{}) *URL {
	return this.Applet.Url(name, args...)
}

// Abort is a helper method that sends an HTTP header and an optional
// body. It is useful for returning 4xx or 5xx errors.
// Once it has been called, any return value from the handler will
// not be written to the response.
func (this *Context) Abort(status int, body string) {
	this.ResponseWriter.WriteHeader(status)
	this.ResponseWriter.Write([]byte(body))
}

// Redirect is a helper method for 3xx redirects.
func (this *Context) Redirect(status int, url_ string) {
	this.ResponseWriter.Header().Set("Location", url_)
	this.ResponseWriter.WriteHeader(status)
	this.ResponseWriter.Write([]byte("Redirecting to: " + url_))
}

// Notmodified writes a 304 HTTP response
func (this *Context) NotModified() {
	this.ResponseWriter.WriteHeader(304)
}

// NotFound writes a 404 HTTP response
func (this *Context) NotFound(message string) {
	this.ResponseWriter.WriteHeader(404)
	this.ResponseWriter.Write([]byte(message))
}

//Unauthorized writes a 401 HTTP response
func (this *Context) Unauthorized() {
	this.ResponseWriter.WriteHeader(401)
}

//Forbidden writes a 403 HTTP response
func (this *Context) Forbidden() {
	this.ResponseWriter.WriteHeader(403)
}

// ContentType sets the Content-Type header for an HTTP response.
// For example, ctx.ContentType("json") sets the content-type to "application/json"
// If the supplied value contains a slash (/) it is set as the Content-Type
// verbatim. The return value is the content type as it was
// set, or an empty string if none was found.
func (this *Context) ContentType(val string) string {
	var ctype string
	if strings.ContainsRune(val, '/') {
		ctype = val
	} else {
		if !strings.HasPrefix(val, ".") {
			val = "." + val
		}
		ctype = mime.TypeByExtension(val)
	}
	if ctype != "" {
		this.Header().Set("Content-Type", ctype)
	}
	return ctype
}

// SetHeader sets a response header. If `unique` is true, the current value
// of that header will be overwritten . If false, it will be appended.
func (this *Context) SetHeader(hdr string, val string, unique bool) {
	if unique {
		this.Header().Set(hdr, val)
	} else {
		this.Header().Add(hdr, val)
	}
}

// SetCookie adds a cookie header to the response.
func (this *Context) SetCookie(cookie *http.Cookie) {
	this.SetHeader("Set-Cookie", cookie.String(), false)
}

func (this *Context) GetCookie(name string) *http.Cookie {
	for _, cookie := range this.Request.Cookies() {
		if cookie.Name != name {
			continue
		}
		return cookie
	}
	return nil
}

func getCookieSig(key string, val []byte, timestamp string) string {
	hm := hmac.New(sha1.New, []byte(key))

	hm.Write(val)
	hm.Write([]byte(timestamp))

	hex := fmt.Sprintf("%02x", hm.Sum(nil))
	return hex
}

func (this *Context) SetSecureCookie(name string, val string, age int64) {
	//base64 encode the val
	if len(this.Applet.Config.CookieSecret) == 0 {
		this.Applet.Logger.Println("Secret Key for secure cookies has not been set. Please assign a cookie secret to web.Config.CookieSecret.")
		return
	}
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	encoder.Write([]byte(val))
	encoder.Close()
	vs := buf.String()
	vb := buf.Bytes()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	sig := getCookieSig(this.Applet.Config.CookieSecret, vb, timestamp)
	cookie := strings.Join([]string{vs, timestamp, sig}, "|")

	this.SetCookie(NewCookie(name, cookie, age))
}

func (this *Context) GetSecureCookie(name string) (string, bool) {
	for _, cookie := range this.Request.Cookies() {
		if cookie.Name != name {
			continue
		}

		parts := strings.SplitN(cookie.Value, "|", 3)

		val := parts[0]
		timestamp := parts[1]
		sig := parts[2]

		if getCookieSig(this.Applet.Config.CookieSecret, []byte(val), timestamp) != sig {
			return "", false
		}

		ts, _ := strconv.ParseInt(timestamp, 0, 64)

		if time.Now().Unix()-31*86400 > ts {
			return "", false
		}

		buf := bytes.NewBufferString(val)
		encoder := base64.NewDecoder(base64.StdEncoding, buf)

		res, _ := ioutil.ReadAll(encoder)
		return string(res), true
	}
	return "", false
}

// small optimization: cache the context type instead of repeteadly calling reflect.Typeof
var contextType reflect.Type

//var defaultStaticDirs []string

func init() {
	contextType = reflect.TypeOf(Context{})
	//find the location of the exe file
	//    wd, _ := os.Getwd()
	//    arg0 := path.Clean(os.Args[0])
	//    var exeFile string
	//    if strings.HasPrefix(arg0, "/") {
	//        exeFile = arg0
	//    } else {
	//        //TODO for robustness, search each directory in $PATH
	//        exeFile = path.Join(wd, arg0)
	//    }
	//    parent, _ := path.Split(exeFile)

	//    defaultStaticDirs = append(defaultStaticDirs, path.Join(parent))
	//    defaultStaticDirs = append(defaultStaticDirs, path.Join(wd))
	return
}
