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

// forwardProxyUrl に渡す auth 情報
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
	forwardProxyUrl   string
	privateForward bool
    forwardProxyAuthMode int
    forwardProxyAuth string
    // 受け入れ可能な IP
    acceptableIPList []net.IPNet
    pacCtrl *PacCtrl
}

func setupGoproxy(proxy *goproxy.ProxyHttpServer) {
	// 処理経過の出力
	proxy.Verbose = true
	// 環境変数の proxy 設定を無視するように
	proxy.Tr.Proxy = nil
	proxy.ConnectDial = nil
}

func newAuthProxyServer(
	port int, forwardProxyUrl string, user string, privateForward bool,
    forwardProxyAuthMode int, forwardProxyAuth string,
    acceptableIPList []net.IPNet, pacUrl string ) *AuthProxyServer {
	log.Printf("forwardProxyUrl: %s\n", forwardProxyUrl)


    var pacCtrl *PacCtrl
    if pacUrl != "" {
        if workPacCtrl, err := getProxyPacCtrl( pacUrl ); err != nil {
            log.Fatal( err )
        } else {
            pacCtrl = workPacCtrl
        }
    }
    //fmt.Print( pacCtrl.getProxyUrlTxt( "https://www.yahoo.co.jp" ) )
    
	authProxyServer := AuthProxyServer{
		map[string]bool{}, forwardProxyUrl, privateForward,
        forwardProxyAuthMode, forwardProxyAuth, acceptableIPList, pacCtrl,
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
        // proxy 認証情報を forwardProxyUrl に渡さない
    } else if proxy.forwardProxyAuthMode == ForwardProxyAuthModePass {
        // この proxy と同じ認証情報を使用する
        forwardReq.Header.Add( ProxyAuthHeaderName, req.Header.Get(ProxyAuthHeaderName) )
    } else if proxy.forwardProxyAuthMode == ForwardProxyAuthModeSpec {
        // 所定の proxy 認証情報を使用する
        forwardReq.Header.Add( ProxyAuthHeaderName, "Basic " + proxy.forwardProxyAuth )
    }
}

func (proxy *AuthProxyServer) getFowardProxyUrl( req *http.Request) string {
    if proxy.pacCtrl == nil {
        return proxy.forwardProxyUrl
    }
    url, err := proxy.pacCtrl.getProxyUrlTxt( req.URL.String() );
    if err != nil {
        log.Fatal( err )
    }
    return url
}

func (proxy *AuthProxyServer) forward(
    forwardProxyUrl string, 
    respWriter http.ResponseWriter, req *http.Request) int {
	log.Printf("forward: %s\n", req.URL.String())

	forwardUrl, err := url.Parse( forwardProxyUrl )
	if err != nil {
		log.Println(err)
		return 500
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(forwardUrl),
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

    forwardProxyUrl := proxy.getFowardProxyUrl( req )

    log.Printf( "forwardProxyUrl -- %s", forwardProxyUrl )

	if forwardProxyUrl == "" {
		// forwardProxyUrl がない場合は、 goproxy に処理を任せる
		log.Printf("proxy: %s", req.URL.String())
		aGoproxy.ServeHTTP(resp, req)
	} else if privateAccess && !proxy.privateForward {
		// forwardProxyUrl が指定されていても private アドレスアクセスの場合は、
		// forwardProxyUrl は使用しない。
		log.Printf("skip forward: %s", req.URL.String())
		aGoproxy.ServeHTTP(resp, req)
	} else if req.Method == "CONNECT" {
		// forwardProxyUrl の指定があり CONNECT の場合は、
		// Proxy-Authenticate を付けなおす。
		log.Printf("forward CONNECT: %s", req.URL.String())
		aGoproxy.ConnectDial = aGoproxy.NewConnectDialToProxyWithHandler(
			forwardProxyUrl, func(forwardReq *http.Request) {
                proxy.setProxyAuth( forwardReq, req )
			})
		aGoproxy.ServeHTTP(resp, req)
	} else {
		// 通常の http 処理で、 forwardProxyUrl が設定されている場合は、
		// ここで forward する。
		code := proxy.forward(forwardProxyUrl, resp, req)
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
	forwardProxyUrl := cmd.String("forward", "", "forward proxy (e.g. http://proxy.addr:port/). pass this auth.")
	privateForward := cmd.Bool("pf", false, "When host is private address, it uses forwarding.")
    forwardProxyAuthModeStr := cmd.String(
        "forwardAuth", "pass",
        "forward proxy auth mode. \n   - none\n   - pass\n   - spec:id:pass\n" )
    acceptableIP := cmd.String(
        "aip", "", "accepable IP. \n  e.g. 192.168.0.1/24\n       192.168.0.1/32" )
    forwardPacUrl := cmd.String(
        "forwardPac", "",
        "forward proxy pac url. e.g. http://proxy.addr/proxy.pac" )

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
        port, *forwardProxyUrl, *userOpt, *privateForward,
        forwardProxyAuthMode, forwardProxyAuth, acceptableIPList, *forwardPacUrl )

	log.Print("start -- ", port)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), proxy))
}
