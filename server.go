package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/elazarl/goproxy"
)

type AuthProxyServer struct {
	// proxy 処理本体 (connect)
	proxyForConnect *goproxy.ProxyHttpServer
	// proxy 処理本体 (非connect)
	proxyForNormal *goproxy.ProxyHttpServer
	// basic 認証の情報 -> true の map
	idPassBasicMap map[string]bool
	// forwardProxy
	forwardProxy   string
	privateForward bool
}

func setupGoproxy(proxy *goproxy.ProxyHttpServer) {
	// 処理経過の出力
	proxy.Verbose = true
	// 環境変数の proxy 設定を無視するように
	proxy.Tr.Proxy = nil
	proxy.ConnectDial = nil
}

func newAuthProxyServer(
	port int, forwardProxy string, user string, privateForward bool) *AuthProxyServer {
	proxyForConnect := goproxy.NewProxyHttpServer()
	proxyForNormal := goproxy.NewProxyHttpServer()

	setupGoproxy(proxyForConnect)
	setupGoproxy(proxyForNormal)

	log.Printf("forwardProxy: %s\n", forwardProxy)
	authProxyServer := AuthProxyServer{
		proxyForConnect, proxyForNormal,
		map[string]bool{}, forwardProxy, privateForward,
	}
	if user != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(user))
		authProxyServer.idPassBasicMap[auth] = true
	}

	return &authProxyServer
}

func (proxy *AuthProxyServer) checkAuth(auth string) string {
	if auth == "" {
		return "not exist auth\n"
	}
	if strings.Index(auth, "Basic ") != 0 {
		return "illegal auth basic\n"
	}
	idpass := auth[6:]
	if _, has := proxy.idPassBasicMap[idpass]; !has {
		return "unmatch id/pass\n"
	}

	return ""
}

func (proxy *AuthProxyServer) forward(respWriter http.ResponseWriter, req *http.Request) int {
	log.Printf("forward: %s\n", req.URL.String())

	forwardProxyUrl, err := url.Parse(proxy.forwardProxy)
	if err != nil {
		log.Println(err)
		return 500
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(forwardProxyUrl),
	}
	client := &http.Client{
		Transport: transport,
	}

	forwardReq, err := http.NewRequest(req.Method, req.URL.String(), nil)
	if err != nil {
		log.Printf("NewRequest: %s", err)
		return 500
	}
	forwardReq.Header = req.Header

	forwardResp, err := client.Do(forwardReq)
	if err != nil {
		log.Printf("Do: %s", err)
		return 500
	}
	//defer forwardReq.Body.Close()

	data, err := ioutil.ReadAll(forwardResp.Body)
	if err != nil {
		log.Println(err)
		return 500
	}

	respWriter.WriteHeader(forwardResp.StatusCode)
	respWriter.Write(data)
	return 0
}

func (proxy *AuthProxyServer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {

	log.Printf("RemoteAddr: %s", req.RemoteAddr)

	if len(proxy.idPassBasicMap) != 0 {
		for key := range req.Header {
			log.Printf("header = %s, val = %s", key, req.Header.Get(key))
		}
		authResult := proxy.checkAuth(req.Header.Get("Proxy-Authorization"))
		if authResult != "" {
			resp.Header().Add("Proxy-Authenticate", "Basic")
			log.Printf(authResult)
			resp.WriteHeader(407)
			return
		}
	}

	privateAccess := false
	if hostIp := net.ParseIP(req.URL.Hostname()); hostIp != nil {
		privateAccess = hostIp.IsPrivate()
	}

	if proxy.forwardProxy == "" {
		// forwardProxy がない場合は、 goproxy に処理を任せる
		log.Printf("proxy: %s", req.URL.String())
		proxy.proxyForNormal.ServeHTTP(resp, req)
	} else if privateAccess && !proxy.privateForward {
		// forwardProxy が指定されていても private アドレスアクセスの場合は、
		// forwardProxy は使用しない。
		log.Printf("skip forward: %s", req.URL.String())
		proxy.proxyForNormal.ServeHTTP(resp, req)
	} else if req.Method == "CONNECT" {
		// forwardProxy の指定があり CONNECT の場合は、
		// Proxy-Authenticate を付けなおす。
		log.Printf("forward CONNECT: %s", req.URL.String())
		proxy.proxyForConnect.ConnectDial = proxy.proxyForConnect.NewConnectDialToProxyWithHandler(
			proxy.forwardProxy, func(forwardReq *http.Request) {
				auth := req.Header.Get("Proxy-Authorization")
				if auth != "" {
					forwardReq.Header.Add("Proxy-Authorization", auth)
				}
			})
		proxy.proxyForConnect.ServeHTTP(resp, req)
	} else {
		// 通常の http 処理で、 forwardProxy が設定されている場合は、
		// ここで forward する。
		code := proxy.forward(resp, req)
		if code != 0 {
			resp.WriteHeader(code)
		}
	}
}

func main() {

	var cmd = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	help := cmd.Bool("help", false, "display help message")
	cmd.Usage = func() {
		fmt.Fprintf(cmd.Output(), "\nUsage: %s options\n\n", os.Args[0])
		fmt.Fprintf(cmd.Output(), " options:\n\n")
		cmd.PrintDefaults()
		os.Exit(1)
	}

	portOpt := cmd.Int("p", 0, "port (mandatory)")
	userOpt := cmd.String("user", "", "proxy id:pass. e.g. id=123, pass=abc, -user 123:abc")
	forwardProxy := cmd.String("forward", "", "forward proxy (http://proxy.addr:port/). pass this auth.")
	privateForward := cmd.Bool("pf", false, "When host is private address, it uses forwarding.")

	cmd.Parse(os.Args[1:])

	port := *portOpt
	if port == 0 {
		cmd.Usage()
	}
	if *help {
		cmd.Usage()
	}

	proxy := newAuthProxyServer(port, *forwardProxy, *userOpt, *privateForward)

	log.Print("start -- ", port)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), proxy))
}
