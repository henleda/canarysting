//go:build darwin || linux

package testgate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"syscall"
	"time"
)

const maxLogBytes = 4 << 20

var credentialPattern = regexp.MustCompile(`(?i)(authorization:\s*bearer\s+[a-z0-9._~+/=-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_-]?key|secret|password)\s*[=:]\s*[^\s]{8,})`)

type commandResult struct {
	output         []byte
	duration       time.Duration
	exitCode       int
	timedOut       bool
	secretFound    bool
	truncated      bool
	processResidue bool
}

func executeCommand(parent context.Context, argv []string, timeout time.Duration, executable string) commandResult {
	started := time.Now()
	if len(argv) == 0 {
		return commandResult{output: []byte("empty command\n"), duration: time.Since(started), exitCode: 2}
	}
	resolved := append([]string(nil), argv...)
	for i := range resolved {
		if resolved[i] == "{testgate}" {
			resolved[i] = executable
		}
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.Command(resolved[0], resolved[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = append(os.Environ(), "NEXT_TELEMETRY_DISABLED=1")
	var output limitedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Start()
	if err != nil {
		return commandResult{output: []byte(fmt.Sprintf("start: %v\n", err)), duration: time.Since(started), exitCode: 127}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var timedOut bool
	select {
	case err = <-done:
	case <-ctx.Done():
		timedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case err = <-done:
		case <-time.After(2 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			err = <-done
		}
	}
	exitCode := 0
	if err != nil {
		exitCode = 1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}
	processResidue := processGroupExists(cmd.Process.Pid)
	if processResidue {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	data := output.Bytes()
	secretFound := output.secretFound
	if secretFound {
		data = []byte("[REDACTED: credential-like material detected; safety stop raised]\n")
	}
	return commandResult{output: data, duration: time.Since(started), exitCode: exitCode, timedOut: timedOut, secretFound: secretFound, truncated: output.truncated, processResidue: processResidue}
}

func processGroupExists(pid int) bool {
	err := syscall.Kill(-pid, 0)
	return err == nil || !errors.Is(err, syscall.ESRCH)
}

type limitedBuffer struct {
	buf         bytes.Buffer
	truncated   bool
	secretFound bool
	scanTail    []byte
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	scan := make([]byte, 0, len(b.scanTail)+len(p))
	scan = append(scan, b.scanTail...)
	scan = append(scan, p...)
	if credentialPattern.Match(scan) {
		b.secretFound = true
	}
	const overlap = 1024
	if len(scan) > overlap {
		b.scanTail = append(b.scanTail[:0], scan[len(scan)-overlap:]...)
	} else {
		b.scanTail = append(b.scanTail[:0], scan...)
	}
	remaining := maxLogBytes - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			b.buf.Write(p[:remaining])
		} else {
			b.buf.Write(p)
		}
	}
	if len(p) > remaining {
		b.truncated = true
	}
	return n, nil
}

func (b *limitedBuffer) Bytes() []byte {
	data := append([]byte(nil), b.buf.Bytes()...)
	if b.truncated {
		data = append(data, []byte("\n[log truncated at 4 MiB]\n")...)
	}
	return data
}
