package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/elazarl/goproxy"
)

type AuthProxyServer struct {
	// proxy 処理本体
	proxy *goproxy.ProxyHttpServer
	// id -> pass の map
	idPassMap map[string]string
	// forwardProxy
	forwardProxy string
}

func newAuthProxyServer(
	port int, forwardProxy string, id, pass string) *AuthProxyServer {
	proxy := goproxy.NewProxyHttpServer()

	proxy.Verbose = true

	log.Printf("forwardProxy: %s\n", forwardProxy)
	authProxyServer := AuthProxyServer{proxy, map[string]string{}, forwardProxy}
	if id != "" && pass != "" {
		authProxyServer.idPassMap[id] = pass
	}

	proxy.ConnectDial = nil
	return &authProxyServer
}

func (proxy *AuthProxyServer) checkAuth(auth string) string {
	if auth == "" {
		return "not exist auth\n"
	}
	if strings.Index(auth, "Basic ") != 0 {
		return "illegal auth basic\n"
	}
	idpassRaw, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return "illegal auth base64\n"
	}
	idpass := string(idpassRaw)
	index := strings.Index(idpass, ":")
	if index == -1 {
		return "illegal auth\n"
	}
	id := idpass[0:index]
	pass := idpass[index+1:]

	if proxy.idPassMap[id] != pass {
		return "unmatch pass\n"
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
	if len(proxy.idPassMap) != 0 {
		for key := range req.Header {
			log.Printf("key = %s", key)
		}
		authResult := proxy.checkAuth(req.Header.Get("Proxy-Authorization"))
		if authResult != "" {
			resp.Header().Add("Proxy-Authenticate", "Basic")
			log.Printf(authResult)
			resp.WriteHeader(407)
			return
		}
	}

	// if req.Method == "CONNECT" || proxy.forwardProxy == "" {
	if proxy.forwardProxy == "" {
		// forwardProxy がない場合は、 goproxy に処理を任せる
		proxy.proxy.ServeHTTP(resp, req)
	} else if req.Method == "CONNECT" {
		// forwardProxy の指定があり CONNECT の場合は、
		// Proxy-Authenticate を付けなおす。
		proxy.proxy.ConnectDial = proxy.proxy.NewConnectDialToProxyWithHandler(
			proxy.forwardProxy, func(forwardReq *http.Request) {
				log.Printf("connect: req hook")
				auth := req.Header.Get("Proxy-Authorization")
				if auth != "" {
					forwardReq.Header.Add("Proxy-Authorization", auth)
				}
			})
		proxy.proxy.ServeHTTP(resp, req)
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
	idOpt := cmd.String("id", "", "id")
	passOpt := cmd.String("pass", "", "password")
	forwardProxy := cmd.String("forward", "", "forward proxy (http://proxy.addr:port/). pass this auth.")

	cmd.Parse(os.Args[1:])

	port := *portOpt
	if port == 0 {
		cmd.Usage()
	}
	if *help {
		cmd.Usage()
	}

	proxy := newAuthProxyServer(port, *forwardProxy, *idOpt, *passOpt)

	log.Print("start -- ", port)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), proxy))
}
