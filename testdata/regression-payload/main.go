package main

import (
	"fmt"
	"os"
	"os/user"
)

var version = "unset"

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--custom-action" {
		current, err := user.Current()
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(os.Args[2], []byte(current.Uid), 0o600); err != nil {
			panic(err)
		}
		return
	}
	fmt.Println(version)
}
