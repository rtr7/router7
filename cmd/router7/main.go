package main

import (
	"flag"
	"log"
)

func logic() error {
	return nil
}

func main() {
	flag.Parse()
	if err := logic(); err != nil {
		log.Fatal(err)
	}
}
