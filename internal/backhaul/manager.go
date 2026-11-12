// Package backhaul invokes the installed Backhaul manager without emulating
// its protocol or translating unsupported options.
package backhaul

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)
var allowed = map[string]bool{
	"create": true, "status": true, "start": true, "stop": true,
	"restart": true, "delete": true, "health": true, "check": true,
	"secret": true, "change-source": true,
}

func Run(args []string) error {
	if len(args) == 0 { return errors.New("expected a documented backhaul-manager command") }
	name := args[0]
	if name == "logs" { return logs(args[1:]) }
	if !allowed[name] { return fmt.Errorf("unsupported command %q; see the installed Backhaul manager documentation", name) }
	for _, arg := range args[1:] {
		if arg == "--root" || strings.HasPrefix(arg, "--root=") || arg == "--test-core-command" {
			return errors.New("simulation/test-only manager options are not allowed by tunnelctl")
		}
	}
	bin := os.Getenv("BACKHAUL_MANAGER")
	if bin == "" { bin = "backhaul-manager" }
	cmd := exec.Command(bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) { return fmt.Errorf("manager exited with status %d", ee.ExitCode()) }
		if strings.Contains(err.Error(), "executable file not found") { return fmt.Errorf("%s not found; install the Backhaul manager package first", bin) }
		return err
	}
	return nil
}

func logs(args []string) error {
	if len(args) != 1 || !idPattern.MatchString(args[0]) { return errors.New("usage: tunnelctl backhaul logs INSTANCE") }
	cmd := exec.Command("journalctl", "--no-pager", "-u", "backhaul-"+args[0]+".service")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil { return fmt.Errorf("journalctl: %w", err) }
	return nil
}
