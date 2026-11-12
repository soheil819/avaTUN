package main

import (
	"fmt"
	"os"

	"tunnelmgr/internal/backhaul"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "backhaul" {
		fmt.Fprintln(os.Stderr, "usage: tunnelctl backhaul <create|status|start|stop|restart|delete|health|check|secret|change-source|logs> [args...]")
		os.Exit(2)
	}
	if err := backhaul.Run(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "tunnelctl:", err)
		os.Exit(1)
	}
}
