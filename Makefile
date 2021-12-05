all:
	go build -o simple-proxy


all-win:
	GOARCH=386 GOOS=windows go build -o simple-proxy.exe server.go
