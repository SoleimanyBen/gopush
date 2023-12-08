package main

import (
	"bufio"
	"fmt"
	"github.com/soleimanyben/gopush/ids"
	"os"
)

func main() {
	//privKey, cert, err := albert.GeneratePushCert()
	//if err != nil {
	//	panic(err)
	//}
	//
	//conn, err := apns.StartConnection(privKey, cert)
	//if err != nil {
	//	panic(err)
	//}
	//defer conn.Close()

	username := os.Getenv("APPLE_USERNAME")
	password := os.Getenv("APPLE_PASSWORD")

	_, err := ids.GenerateAuthToken(username, password, callback)
	if err != nil {
		panic(err)
	}
}

func callback() (string, error) {
	r := bufio.NewReader(os.Stdin)

	fmt.Print("Enter 2FA Code: ")

	code, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}

	return code, nil
}
