package main

import (
	"github.com/soleimanyben/go-imessage/albert"
	"github.com/soleimanyben/go-imessage/apns"
)

func main() {
	privKey, cert, err := albert.GeneratePushCert()
	if err != nil {
		panic(err)
	}

	conn, err := apns.StartConnection(privKey, cert)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
}
