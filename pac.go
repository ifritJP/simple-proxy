package main

import (
	"net/http"
	"net/url"
	"io/ioutil"
	"os"
	"log"
    "github.com/darren/gpac"
    "strings"
)

type PacCtrl struct {
    pac *gpac.Parser
    scheme string
}

func getProxyPacCtrl( pacUrl string ) (*PacCtrl, error) {

    jsCode := ""

    
    fileScheme := "file://"
    if strings.Index( pacUrl, fileScheme ) == 0 {
        fileObj, err := os.Open( pacUrl[ len( fileScheme ): ] )
        if err != nil {
            return nil, err
        }
        defer fileObj.Close()
        data, err := ioutil.ReadAll(fileObj)
        if err != nil {
            log.Println(err)
            return nil, err
        }
        jsCode = string(data)
        
    } else {
        transport := &http.Transport{
        }
        client := &http.Client{
            Transport: transport,
        }

        forwardReq, err := http.NewRequest( "GET", pacUrl, nil)
        if err != nil {
            log.Printf("NewRequest: %s", err)
            return nil, err
        }
        
        
        forwardResp, err := client.Do(forwardReq)
        if err != nil {
            log.Printf("Do: %s", err)
            return nil, err
        }
        //defer forwardReq.Body.Close()

        data, err := ioutil.ReadAll(forwardResp.Body)
        if err != nil {
            log.Println(err)
            return nil, err
        }
        jsCode = string(data)
    }

    pac, err := gpac.New( jsCode )
    if err != nil {
        return nil, err
    }

	pacUrlInfo, err := url.Parse( pacUrl )
	if err != nil {
		return nil, err
	}
    
    return &PacCtrl{ pac, pacUrlInfo.Scheme }, nil
}

func (pacCtrl *PacCtrl) getProxyUrlTxt( url string ) (string, error) {
    resp, err := pacCtrl.pac.FindProxyForURL( url )
    if err != nil {
        return "", err
    }

    if resp == "DIRECT" {
        return "", nil
    }
    if strings.Index( resp, "PROXY " ) != -1 {
        // ゴミを除去
        proxyUrl := strings.ReplaceAll( resp[ len( "PROXY " ): ], ";", "" )
        return pacCtrl.scheme + "://" + proxyUrl, nil
    }
    log.Fatalf( "not support -- %v", resp )
    
    return "", nil
}
