//go:build unix

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
)

// maybeReexecDemoAsUnprivileged: Postgres' initdb refuses to run as root, which
// is exactly the situation in a bare `docker run debian` / CI box. When the
// demo DB is needed and we're root on Linux, copy this binary somewhere world-
// readable and re-exec `faultwall try` as `nobody`. Returns handled=true if the
// child ran (its exit code is returned).
func maybeReexecDemoAsUnprivileged(args []string) (handled bool, code int, err error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || os.Getenv("FAULTWALL_TRY_CHILD") == "1" {
		return false, 0, nil
	}
	uid, gid := 65534, 65534
	if u, lerr := user.Lookup("nobody"); lerr == nil {
		if v, e := strconv.Atoi(u.Uid); e == nil {
			uid = v
		}
		if v, e := strconv.Atoi(u.Gid); e == nil {
			gid = v
		}
	}
	dir := filepath.Join(os.TempDir(), "faultwall-try-nobody")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, 0, err
	}
	_ = os.Chown(dir, uid, gid)
	self, err := os.Executable()
	if err != nil {
		return false, 0, err
	}
	dst := filepath.Join(dir, "faultwall")
	if err := copyExecutable(self, dst); err != nil {
		return false, 0, err
	}
	fmt.Println("  (running as root — starting the demo as user 'nobody', since Postgres refuses to run as root)")
	cmd := exec.Command(dst, append([]string{"try"}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HOME="+dir, "FAULTWALL_TRY_CHILD=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if err := cmd.Start(); err != nil {
		return false, 0, err
	}
	// Signals (Ctrl+C) reach the child via the shared process group; just wait.
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return true, ee.ExitCode(), nil
		}
		return true, 1, err
	}
	return true, 0, nil
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
