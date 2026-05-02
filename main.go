package main

import (
	"os"

	"github.com/evgenybalyakin/sudocheck/cmd"
)

var version = "dev"

func main() {
	exitCode := cmd.Execute(os.Args[1:], os.Stdout, os.Stderr, version)
	os.Exit(exitCode)
}
