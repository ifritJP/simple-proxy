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

// forwardProxy に渡す auth 情報
// なし
const ForwardProxyAuthModeNone = 0
// この proxy と同じ
const ForwardProxyAuthModePass = 1
// 別に指定
const ForwardProxyAuthModeSpec = 2

// proxy-authorization ヘッダ名
const ProxyAuthHeaderName = "proxy-authorization"


type AuthProxyServer struct {
	// basic 認証の情報 -> true の map
	idPassBasicMap map[string]bool
	// forwardProxy
	forwardProxy   string
	privateForward bool
    forwardProxyAuthMode int
    forwardProxyAuth string
    // 受け入れ可能な IP
    acceptableIPList []net.IPNet
}

func setupGoproxy(proxy *goproxy.ProxyHttpServer) {
	// 処理経過の出力
	proxy.Verbose = true
	// 環境変数の proxy 設定を無視するように
	proxy.Tr.Proxy = nil
	proxy.ConnectDial = nil
}

func newAuthProxyServer(
	port int, forwardProxy string, user string, privateForward bool,
    forwardProxyAuthMode int, forwardProxyAuth string,
    acceptableIPList []net.IPNet ) *AuthProxyServer {
	log.Printf("forwardProxy: %s\n", forwardProxy)
	authProxyServer := AuthProxyServer{
		map[string]bool{}, forwardProxy, privateForward,
        forwardProxyAuthMode, forwardProxyAuth, acceptableIPList,
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

// モードに応じて proxy 認証情報を設定
//
// @param forwardReq forward 先の proxy の request
// @param req forward 元の request
func (proxy *AuthProxyServer) setProxyAuth( forwardReq, req *http.Request ) {
    if proxy.forwardProxyAuthMode == ForwardProxyAuthModeNone {
        // proxy 認証情報を forwardProxy に渡さない
    } else if proxy.forwardProxyAuthMode == ForwardProxyAuthModePass {
        // この proxy と同じ認証情報を使用する
        forwardReq.Header.Add( ProxyAuthHeaderName, req.Header.Get(ProxyAuthHeaderName) )
    } else if proxy.forwardProxyAuthMode == ForwardProxyAuthModeSpec {
        // 所定の proxy 認証情報を使用する
        forwardReq.Header.Add( ProxyAuthHeaderName, "Basic " + proxy.forwardProxyAuth )
    }
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
    // ヘッダ設定を一旦 clone し、proxy 認証情報 を削除する。
    forwardReq.Header = req.Header.Clone()
    forwardReq.Header.Del( ProxyAuthHeaderName )

    // モードに応じて proxy 認証情報を設定
    proxy.setProxyAuth( forwardReq, req )
        
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

func (proxy *AuthProxyServer) checkAccept( req *http.Request ) bool {
    if len( proxy.acceptableIPList ) == 0 {
        return true
    }
    addrTxt := req.RemoteAddr
    if loc := strings.Index( addrTxt, ":" ); loc != -1 {
        addrTxt = addrTxt[:loc]
    }
    
    if remoteAddr := net.ParseIP( addrTxt ); remoteAddr != nil {
        for _, acceptableIP := range( proxy.acceptableIPList ) {
            if acceptableIP.Contains( remoteAddr ) {
                return true
            }
        }
    }
    log.Printf( "reject access from %v", req.RemoteAddr )
    return false
}

func (proxy *AuthProxyServer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {

	log.Printf("RemoteAddr: %v, %s", req.URL.IsAbs(), req.RemoteAddr )
    if !proxy.checkAccept( req ) {
        resp.WriteHeader(400)
        return
    }

	if len(proxy.idPassBasicMap) != 0 {
		for key := range req.Header {
			log.Printf("header = %s, val = %s", key, req.Header.Get(key))
		}
		authResult := proxy.checkAuth(req.Header.Get(ProxyAuthHeaderName))
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

	aGoproxy := goproxy.NewProxyHttpServer()
	setupGoproxy( aGoproxy )

	if proxy.forwardProxy == "" {
		// forwardProxy がない場合は、 goproxy に処理を任せる
		log.Printf("proxy: %s", req.URL.String())
		aGoproxy.ServeHTTP(resp, req)
	} else if privateAccess && !proxy.privateForward {
		// forwardProxy が指定されていても private アドレスアクセスの場合は、
		// forwardProxy は使用しない。
		log.Printf("skip forward: %s", req.URL.String())
		aGoproxy.ServeHTTP(resp, req)
	} else if req.Method == "CONNECT" {
		// forwardProxy の指定があり CONNECT の場合は、
		// Proxy-Authenticate を付けなおす。
		log.Printf("forward CONNECT: %s", req.URL.String())
		aGoproxy.ConnectDial = aGoproxy.NewConnectDialToProxyWithHandler(
			proxy.forwardProxy, func(forwardReq *http.Request) {
                proxy.setProxyAuth( forwardReq, req )
			})
		aGoproxy.ServeHTTP(resp, req)
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
    forwardProxyAuthModeStr := cmd.String(
        "forwardAuth", "pass",
        "forward proxy auth mode. \n   - none\n   - pass\n   - spec:id:pass\n" )
    acceptableIP := cmd.String(
        "aip", "", "accepable IP. \n  e.g. 192.168.0.1/24\n       192.168.0.1/32" )

	cmd.Parse(os.Args[1:])

	port := *portOpt
	if port == 0 {
		cmd.Usage()
	}
	if *help {
		cmd.Usage()
	}

    forwardProxyAuthMode := ForwardProxyAuthModeNone
    forwardProxyAuth := ""
    if *forwardProxyAuthModeStr == "none" {
        forwardProxyAuthMode = ForwardProxyAuthModeNone
    } else if *forwardProxyAuthModeStr == "pass" {
        forwardProxyAuthMode = ForwardProxyAuthModePass
    } else if strings.Index( *forwardProxyAuthModeStr, "spec:" ) == 0 {
        forwardProxyAuthMode = ForwardProxyAuthModeSpec
        auth := (*forwardProxyAuthModeStr)[ len( "spec:" ): ]
        forwardProxyAuth = base64.StdEncoding.EncodeToString([]byte(auth))
    } else {
        cmd.Usage()
    }

    acceptableIPList := []net.IPNet{}
    if _, ipnet, err := net.ParseCIDR( *acceptableIP ); err == nil {
        log.Printf( "aip %v", *ipnet )
        acceptableIPList = append( acceptableIPList, *ipnet )
    }

	proxy := newAuthProxyServer(
        port, *forwardProxy, *userOpt, *privateForward,
        forwardProxyAuthMode, forwardProxyAuth, acceptableIPList )

	log.Print("start -- ", port)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), proxy))
}
