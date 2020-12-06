package main

import (
	"fmt"
	"log"

	"github.com/sinambela/easybuffer/bytesbuff"
	"github.com/sinambela/easyeddsa/easyeddsa"
)

func main() {
	poolx := bytesbuff.GetBytesBuffer()

	eddsax, err := easyeddsa.GetEasyEDDSA(poolx)
	if err != nil {
		log.Fatalln(err)
	}

	pubK, privK, err := eddsax.KeyTostring()
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("pubK : ", pubK)

	fmt.Println("privK : ", privK)

	pubKStr := `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEApy6ZwDAODmgS5iF82+pjbMv/kEhWo+24reXVK8qjF9Q=
-----END PUBLIC KEY-----
	`

	privKStr := `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMKzJfB6iEOEqA/gA2tmNuZVeiPZ9OnqcMxHzSchTv8i
-----END PRIVATE KEY-----
	`

	obj, err := easyeddsa.StringToKeyObject(pubKStr, privKStr, poolx)
	if err != nil {
		log.Fatalln(err)
	}

	pubkx, privkx, err := obj.KeyTostring()
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("pub kx : ", pubkx)

	fmt.Println("priv kx : ", privkx)
}
