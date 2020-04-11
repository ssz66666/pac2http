// Package pac2http provides a convenient interface to build a http proxy
// from a proxy auto config file
package pac2http

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/goburrow/cache"
	"github.com/jackwakefield/gopac"
	"golang.org/x/net/proxy"
	goproxy "gopkg.in/elazarl/goproxy.v1"
)

// DirectDialer is the net.Dialer used for direct connection
// and forwarding to proxy servers
var DirectDialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
	DualStack: true,
}

// PacProxyHTTPServer implements http.Handler interface which acts as a http proxy
// and serve traffic using the pac file
type PacProxyHTTPServer struct {
	Proxy     *goproxy.ProxyHttpServer
	PacParser *gopac.Parser
	mux       sync.Mutex
}

// PacProxyDialer implements net.Dialer interface which uses pac file to determine
// the underlying Dialer to use
type PacProxyDialer struct {
	ProxyFunc  func(string) (string, error)
	DialerMap  cache.LoadingCache //[string]Dialer, "DIRECT" or a URL string
	ProxyCache cache.LoadingCache // [string]Dialer
}

func cacheStringToDialer(pr cache.Key) (cache.Value, error) {
	k := pr.(string)
	return stringToDialer(k)
}

func stringToDialer(pr string) (proxy.Dialer, error) {
	if pr == "DIRECT" {
		return DirectDialer, nil
	}
	u, err := url.Parse(pr)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "http" || u.Scheme == "https" || u.Scheme == "socks5" {
		dialer, err := proxy.FromURL(u, DirectDialer)
		if err != nil {
			return nil, err
		}
		return dialer, nil
	}
	return nil, fmt.Errorf("Unrecognised proxy protocol: %s", u.Scheme)
}

// NewPacProxyDialer creates an instance of PacProxyDialer with given proxy function
func NewPacProxyDialer(proxyFunc func(string) (string, error), cacheOptions ...cache.Option) *PacProxyDialer {
	d := &PacProxyDialer{
		ProxyFunc: proxyFunc,
		DialerMap: cache.NewLoadingCache(
			cacheStringToDialer,
		),
		ProxyCache: nil,
	}
	d.ProxyCache = cache.NewLoadingCache(
		func(k cache.Key) (cache.Value, error) {
			hostname := k.(string)
			pr, err := proxyFunc(hostname)
			if err != nil {
				return nil, err
			}
			return d.DialerMap.Get(pr)
		},
		cacheOptions...,
	)
	return d
}

// Dial works like net.Dialer.Dial for a PacProxyDialer
func (p *PacProxyDialer) Dial(network string, hostname string) (net.Conn, error) {
	f, err := p.ProxyCache.Get(hostname)
	if err != nil {
		return nil, err
	}
	d := f.(proxy.Dialer)
	return d.Dial(network, hostname)
}

// DialContext works like net.Dialer.DialContext for a PacProxyDialer
func (p *PacProxyDialer) DialContext(ctx context.Context, network string, hostname string) (net.Conn, error) {
	f, err := p.ProxyCache.Get(hostname)
	if err != nil {
		return nil, err
	}
	if d, ok := f.(proxy.ContextDialer); ok {
		return d.DialContext(ctx, network, hostname)
	}
	d := f.(proxy.Dialer)

	// copied from https://github.com/golang/net/blob/d3edc9973b7eb1fb302b0ff2c62357091cea9a30/proxy/dial.go#L35
	var (
		conn net.Conn
		done = make(chan struct{}, 1)
	)
	go func() {
		conn, err = d.Dial(network, hostname)
		close(done)
		if conn != nil && ctx.Err() != nil {
			conn.Close()
		}
	}()
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-done:
	}
	return conn, err
}

// StringOrError represents either a string or error
type StringOrError struct {
	String string
	Err    error
}

// PacEntryToProxyString converts a pac entry string to a *StringOrError array containing "DIRECT", or a proxy url string, or an error
func PacEntryToProxyString(entry string) []*StringOrError {
	prs := strings.Split(entry, ";")
	results := make([]*StringOrError, len(prs))
	for i, pr := range prs {
		pr = strings.TrimSpace(pr)
		if pr != "DIRECT" {
			prSegs := strings.SplitN(pr, " ", 2)
			if prSegs[0] == "PROXY" || prSegs[0] == "HTTP" {
				prSegs[0] = "http://"
			} else if prSegs[0] == "HTTPS" {
				prSegs[0] = "https://"
			} else if prSegs[0] == "SOCKS" {
				prSegs[0] = "socks5://" // should it be "socks://" instead?
			} else if prSegs[0] == "SOCKS4" {
				prSegs[0] = "socks4://"
			} else if prSegs[0] == "SOCKS5" {
				prSegs[0] = "socks5://"
			} else {
				results[i] = &StringOrError{"", fmt.Errorf("Unrecognised proxy protocol: %s", prSegs[0])}
			}
			results[i] = &StringOrError{strings.Join(prSegs, ""), nil}
		} else {
			results[i] = &StringOrError{pr, nil}
		}
	}
	return results

}

// TransportProxyFromPac takes a thread-safe FindProxyForURL(url string, hostname string) (string, error) function,
// returns a func(*url.URL) (*url.URL, error), which return nil for DIRECT or *url.URL for proxy.
func TransportProxyFromPac(findProxyForURL func(string, string) (string, error)) func(*url.URL) (*url.URL, error) {
	return func(req *url.URL) (*url.URL, error) {
		log.Printf("Finding proxy for URL: %s\n", req.String())
		proxy, err := findProxyForURL(req.String(), req.Hostname())
		if err != nil {
			log.Printf("ERR: Proxy entry not found for URL: %s\n", req.String())
			return nil, err
		}

		strOrErr := PacEntryToProxyString(proxy)[0]
		purlstr := strOrErr.String
		err = strOrErr.Err
		if err != nil {
			return nil, err
		}
		if purlstr == "DIRECT" {
			log.Printf("DIRECT for URL: %s\n", req.String())
			return nil, nil
		}
		purl, err := url.Parse(purlstr)
		if err != nil {
			log.Printf("ERR: failed to parse proxy string %s\n", purlstr)
			return nil, err
		}
		log.Printf("PROXY %s for %s\n", purl.String(), req.String())
		return purl, nil
	}
}

// ProxyStringFromPac takes a thread-safe FindProxyForURL(url string, hostname string) (string, error) function,
// returns a func(string) (string, error), which return "DIRECT" for DIRECT or string url for proxy.
func ProxyStringFromPac(findProxyForURL func(string, string) (string, error)) func(string) (string, error) {
	return func(hostname string) (string, error) {
		hst, _, _ := net.SplitHostPort(hostname)
		log.Printf("Finding proxy for hostname: %s\n", hostname)
		proxy1, err1 := findProxyForURL("http://"+hostname, hst)
		proxy2, err2 := findProxyForURL("https://"+hostname, hst)
		if err1 != nil {
			log.Printf("ERR: Proxy entry not found for hostname: http://%s\n", hostname)
			return "", err1
		}
		if err2 != nil {
			log.Printf("ERR: Proxy entry not found for hostname: https://%s\n", hostname)
			return "", err2
		}
		strOrErr := PacEntryToProxyString(proxy1)[0]
		p1 := strOrErr.String
		err1 = strOrErr.Err
		strOrErr = PacEntryToProxyString(proxy2)[0]
		p2 := strOrErr.String
		err2 = strOrErr.Err
		if err1 != nil {
			log.Printf("ERR: failed to parse proxy string %s\n", p1)
			return "", err1
		}
		if err2 != nil {
			log.Printf("ERR: failed to parse proxy string %s\n", p2)
			return "", err2
		}
		if p1 != "DIRECT" {
			log.Printf("PROXY %s for hostname %s\n", p1, hostname)
			return p1, nil
		}
		if p2 != "DIRECT" {
			log.Printf("PROXY %s for hostname %s\n", p2, hostname)
		} else {
			log.Printf("DIRECT for hostname %s\n", hostname)
		}
		return p2, nil
	}
}

// GetProxyFunc converts the pac to a proxy function,
// used by PacProxyDialer to give a net.Dialer.Dial function
func (svr *PacProxyHTTPServer) GetProxyFunc() func(string) (string, error) {
	return func(hostname string) (string, error) {
		pac := svr.PacParser
		hst, _, _ := net.SplitHostPort(hostname)
		log.Printf("Finding proxy for hostname: %s\n", hostname)
		svr.mux.Lock()
		proxy1, err1 := pac.FindProxy("http://"+hostname, hst)
		proxy2, err2 := pac.FindProxy("https://"+hostname, hst)
		svr.mux.Unlock()
		if err1 != nil {
			log.Printf("ERR: Proxy entry not found for hostname: http://%s\n", hostname)
			return "", err1
		}
		if err2 != nil {
			log.Printf("ERR: Proxy entry not found for hostname: https://%s\n", hostname)
			return "", err2
		}
		strOrErr := PacEntryToProxyString(proxy1)[0]
		p1 := strOrErr.String
		err1 = strOrErr.Err
		strOrErr = PacEntryToProxyString(proxy2)[0]
		p2 := strOrErr.String
		err2 = strOrErr.Err
		if err1 != nil {
			log.Printf("ERR: failed to parse proxy string %s\n", p1)
			return "", err1
		}
		if err2 != nil {
			log.Printf("ERR: failed to parse proxy string %s\n", p2)
			return "", err2
		}
		if p1 != "DIRECT" {
			log.Printf("PROXY %s for hostname %s\n", p1, hostname)
			return p1, nil
		}
		if p2 != "DIRECT" {
			log.Printf("PROXY %s for hostname %s\n", p2, hostname)
		} else {
			log.Printf("DIRECT for hostname %s\n", hostname)
		}
		return p2, nil

	}
}

// GetProxy converts the pac to a proxy function usable for Transport.Proxy
func (svr *PacProxyHTTPServer) GetProxy() func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		return TransportProxyFromPac(func(u string, h string) (string, error) {
			pac := svr.PacParser
			svr.mux.Lock()
			proxy, err := pac.FindProxy(req.URL.String(), req.URL.Hostname())
			svr.mux.Unlock()
			return proxy, err
		})(req.URL)
	}
}

func (svr *PacProxyHTTPServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	svr.Proxy.ServeHTTP(w, req)
}

// NewPacProxyHTTPServerWithPath is a convenience function to create an instance of
// PacProxyHTTPServer with a local PAC file.
func NewPacProxyHTTPServerWithPath(path string) (*PacProxyHTTPServer, error) {
	parser := new(gopac.Parser)
	err := parser.Parse(path)
	if err != nil {
		return nil, err
	}
	return NewPacProxyHTTPServer(parser), nil
}

// NewPacProxyHTTPServerWithURL is a convenience function to create an instance of
// PacProxyHTTPServer with a remote PAC URL.
func NewPacProxyHTTPServerWithURL(url string) (*PacProxyHTTPServer, error) {
	parser := new(gopac.Parser)
	err := parser.ParseUrl(url)
	if err != nil {
		return nil, err
	}
	return NewPacProxyHTTPServer(parser), nil
}

// NewPacProxyHTTPServer creates an instance of
// PacProxyHTTPServer with the given initialised gopac.Parser.
func NewPacProxyHTTPServer(parser *gopac.Parser) *PacProxyHTTPServer {
	p := new(PacProxyHTTPServer)
	p.Proxy = goproxy.NewProxyHttpServer()
	p.PacParser = parser
	p.Proxy.Tr.Proxy = p.GetProxy()
	p.Proxy.ConnectDial = NewPacProxyDialer(
		p.GetProxyFunc(),
		cache.WithMaximumSize(10000),
		cache.WithPolicy("tinylfu"),
	).Dial
	return p
}
