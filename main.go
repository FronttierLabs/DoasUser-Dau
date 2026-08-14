package main

import (
	"fmt"
	"log/syslog"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const Version = "v1.2.0-kestrel-patched"

var sysLog *syslog.Writer

func initAudit() {
	w, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_INFO, "dau")
	if err != nil {
		fmt.Fprintf(os.Stderr, "dau: syslog unavailable\n")
		return
	}
	sysLog = w
}

func auditLog(tag, msg string) {
	line := fmt.Sprintf("[%s] %s", tag, msg)
	if sysLog != nil {
		_ = sysLog.Info(line)
	}
	fmt.Fprintf(os.Stderr, "dau-audit: %s\n", line)
}

var verbose bool

func vlogf(format string, a ...any) {
	if verbose {
		fmt.Fprintf(os.Stderr, "dau-verbose: "+format+"\n", a...)
	}
}

// FIX H1: only root may see verbose output. Unprivileged users must not be
// able to read the root-only /etc/dau.conf through `dau -v`.
func gateVerbose(ruid uint32) {
	verbose = verbose && ruid == 0
}

func safeUint32(v int) uint32 {
	if v < 0 || v > 0xFFFFFFFF {
		fatal("uid/gid out of range")
	}
	return uint32(v)
}

func getRealUID() uint32      { return safeUint32(syscall.Getuid()) }
func getRealGID() uint32      { return safeUint32(syscall.Getgid()) }
func getEffectiveUID() uint32 { return safeUint32(syscall.Geteuid()) }

func getSupplementaryGIDs() []uint32 {
	gids, err := syscall.Getgroups()
	if err != nil {
		return nil
	}
	primary := getRealGID()
	out := make([]uint32, 0, len(gids)+1)
	out = append(out, primary)
	for _, g := range gids {
		if gu := safeUint32(g); gu != primary {
			out = append(out, gu)
		}
	}
	return out
}

func dropToUser(uid, gid uint32) error {
	if err := unix.Setgroups([]int{int(gid)}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := unix.Setresgid(-1, int(gid), 0); err != nil {
		return fmt.Errorf("setresgid: %w", err)
	}
	if err := unix.Setresuid(-1, int(uid), 0); err != nil {
		return fmt.Errorf("setresuid: %w", err)
	}
	vlogf("dropped to invoker uid=%d gid=%d", uid, gid)
	return nil
}

func regainRoot() error {
	if err := unix.Setresuid(-1, 0, 0); err != nil {
		return fmt.Errorf("regain setresuid: %w", err)
	}
	if err := unix.Setresgid(-1, 0, 0); err != nil {
		return fmt.Errorf("regain setresgid: %w", err)
	}
	vlogf("re-acquired root")
	return nil
}

func setTargetCredentials(uid, gid uint32) error {
	if err := unix.Setresgid(int(gid), int(gid), int(gid)); err != nil {
		return fmt.Errorf("setresgid(target): %w", err)
	}
	if err := unix.Setresuid(int(uid), int(uid), int(uid)); err != nil {
		return fmt.Errorf("setresuid(target): %w", err)
	}
	vlogf("target credentials set uid=%d gid=%d", uid, gid)
	return nil
}

const safePATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

var envTokenRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.@-]*$`)
var usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var allowedLocales = map[string]struct{}{
	"C": {}, "POSIX": {}, "C.UTF-8": {}, "en_US.UTF-8": {}, "en_GB.UTF-8": {},
}

func envValueAllowed(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	return envTokenRe.MatchString(v)
}

func sanitizeEnv(targetUser *user.User) []string {
	safe := map[string]string{
		"HOME":    targetUser.HomeDir,
		"USER":    targetUser.Username,
		"LOGNAME": targetUser.Username,
		"SHELL":   getUserShell(targetUser.Username),
		"PATH":    safePATH,
	}
	if t := os.Getenv("TERM"); envValueAllowed(t) {
		safe["TERM"] = t
	}
	for _, k := range []string{"LANG", "LC_ALL"} {
		if l := os.Getenv(k); envValueAllowed(l) {
			if _, ok := allowedLocales[l]; ok {
				safe[k] = l
			}
		}
	}
	env := make([]string, 0, len(safe))
	for k, v := range safe {
		if v != "" {
			env = append(env, k+"="+v)
		}
	}
	vlogf("env: final child env = %q", env)
	return env
}

func dirTrustworthy(dir string) bool {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if st.Uid != 0 {
		return false
	}
	if fi.Mode().Perm()&0022 != 0 {
		return false
	}
	return true
}

func resolveCommand(cmd string) string {
	if filepath.IsAbs(cmd) {
		return cmd
	}
	for _, dir := range filepath.SplitList(safePATH) {
		if !dirTrustworthy(dir) {
			continue
		}
		candidate := filepath.Join(dir, cmd)
		fi, err := os.Stat(candidate)
		if err == nil && !fi.IsDir() {
			return candidate
		}
	}
	return ""
}

func verifyTrustedBinary(fd int, path string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("fstat: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("not a regular file")
	}

	// FIX M3: scripts would execute the shebang interpreter, which has not
	// passed the trusted-binary checks. Reject them.
	var hdr [2]byte
	n, err := unix.Pread(fd, hdr[:], 0)
	if err != nil && err != unix.EINTR {
		return fmt.Errorf("read: %w", err)
	}
	if n == 2 && hdr[0] == '#' && hdr[1] == '!' {
		return fmt.Errorf("scripts are not allowed")
	}

	if st.Mode&0111 == 0 {
		return fmt.Errorf("not executable")
	}
	if st.Uid != 0 {
		return fmt.Errorf("not owned by root")
	}
	if st.Mode&0022 != 0 {
		return fmt.Errorf("group/other writable")
	}
	if !dirTrustworthy(filepath.Dir(path)) {
		return fmt.Errorf("parent directory not trusted")
	}
	vlogf("verifyTrustedBinary: %s ok", path)
	return nil
}

func getUserShell(username string) string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "/bin/sh"
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 7 && fields[0] == username {
			return fields[6]
		}
	}
	return "/bin/sh"
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: dau [-v] [-u target_user] [--] command [args…]
	-v, --verbose   root-only exhaustive trace on stderr (debug only)
	`)
	os.Exit(1)
}

type cliArgs struct {
	TargetUser string
	Command    string
	Args       []string
}

func parseArgs() cliArgs {
	a := cliArgs{TargetUser: "root"}
	osArgs := os.Args[1:]
	i := 0
	for i < len(osArgs) {
		arg := osArgs[i]
		switch {
			case arg == "-version" || arg == "--version":
				fmt.Printf("dau %s\n", Version)
				os.Exit(0)
			case arg == "-v" || arg == "--verbose":
				verbose = true
			case arg == "-u" || arg == "--user":
				i++
				if i >= len(osArgs) {
					usage()
				}
				a.TargetUser = osArgs[i]
			case strings.HasPrefix(arg, "-u="):
				a.TargetUser = arg[3:]
			case arg == "--":
				i++
				goto done
			case strings.HasPrefix(arg, "-") && arg != "-":
				usage()
			default:
				goto done
		}
		i++
	}
	done:
	if i < len(osArgs) {
		a.Command = osArgs[i]
		a.Args = osArgs[i:]
	}
	return a
}

func stringsToNilPtrs(ss []string) []*byte {
	n := 0
	for _, s := range ss {
		n += len(s) + 1
	}
	buf := make([]byte, n)
	ps := make([]*byte, 0, len(ss)+1)
	for _, s := range ss {
		copy(buf, s)
		ps = append(ps, &buf[0])
		buf = buf[len(s)+1:]
	}
	ps = append(ps, nil)
	return ps
}

func execveat(dirfd int, path string, argv, envv []string, flags int) error {
	argvPtrs := stringsToNilPtrs(argv)
	envPtrs := stringsToNilPtrs(envv)
	pb := append([]byte(path), 0)
	pathPtr := &pb[0]
	_, _, errno := unix.Syscall6(unix.SYS_EXECVEAT,
				     uintptr(dirfd),
				     uintptr(unsafe.Pointer(pathPtr)),
				     uintptr(unsafe.Pointer(&argvPtrs[0])),
				     uintptr(unsafe.Pointer(&envPtrs[0])),
				     uintptr(flags),
				     0)
	if errno != 0 {
		return errno
	}
	return nil
}

func main() {
	syscall.Umask(0022)
	initAudit()

	euid := getEffectiveUID()
	ruid := getRealUID()
	if euid != 0 {
		fatal("dau must be installed setuid-root (euid=%d)", euid)
	}
	auditLog("START", fmt.Sprintf("version=%s invoker_uid=%d target=pending", Version, ruid))

	cli := parseArgs()

	// FIX H1: disable verbose for non-root before policy is read/printed.
	gateVerbose(ruid)
	setPamVerbose(verbose)
	vlogf("args: target=%q cmd=%q args=%q", cli.TargetUser, cli.Command, cli.Args)

	if !usernameRe.MatchString(cli.TargetUser) {
		fatal("invalid target username %q", cli.TargetUser)
	}
	targetU, err := user.Lookup(cli.TargetUser)
	if err != nil {
		if ruid == 0 {
			fatal("unknown target user %q: %v", cli.TargetUser, err)
		}
		fatal("unknown target user")
	}
	targetUID, err := strconv.ParseUint(targetU.Uid, 10, 32)
	if err != nil {
		fatal("malformed target UID (fail closed)")
	}
	targetGID, err := strconv.ParseUint(targetU.Gid, 10, 32)
	if err != nil {
		fatal("malformed target GID (fail closed)")
	}

	if cli.Command == "" {
		fatal("no command specified")
	}
	cmdArgs := []string{}
	if len(cli.Args) > 1 {
		cmdArgs = cli.Args[1:]
	}

	cfg := loadConfig()
	vlogf("policy loaded: %d rule(s)", len(cfg.Rules))

	invokerGIDs := getSupplementaryGIDs()
	if err := dropToUser(ruid, getRealGID()); err != nil {
		fatal("drop privileges failed")
	}

	// FIX H2: resolve and canonicalize as the invoker, not as root.
	// Root-resolution was an unauthenticated existence/attribute oracle for
	// root-only paths such as /root/only/*.
	resolvedCmd := resolveCommand(cli.Command)
	if resolvedCmd == "" {
		if ruid == 0 {
			fatal("cannot resolve %q via safe PATH", cli.Command)
		}
		fatal("permission denied")
	}

	realCmd, err := filepath.EvalSymlinks(resolvedCmd)
	if err != nil {
		if ruid == 0 {
			fatal("cannot resolve symlinks for %q: %v", resolvedCmd, err)
		}
		fatal("permission denied")
	}
	if !dirTrustworthy(filepath.Dir(realCmd)) {
		if ruid == 0 {
			fatal("resolved target %q lives in untrusted directory", realCmd)
		}
		fatal("permission denied")
	}

	// FIX H3: authorize the canonical resolved path before opening the binary
	// and before any password prompt.
	rule := cfg.findRule(ruid, invokerGIDs, cli.TargetUser, realCmd, cmdArgs)
	if rule == nil {
		auditLog("DENY", fmt.Sprintf("uid=%d target=%s cmd=%s args=%q – no matching rule",
					     ruid, cli.TargetUser, realCmd, cmdArgs))
		fatal("permission denied: no matching rule for uid %d → %s (%s %q)",
		      ruid, cli.TargetUser, realCmd, cmdArgs)
	}
	if rule.Command == "" || rule.Args == argsAny {
		auditLog("GRANT_UNRESTRICTED", fmt.Sprintf("uid=%d target=%s cmd=%s args=%q",
							   ruid, cli.TargetUser, realCmd, cmdArgs))
	}

	if err := regainRoot(); err != nil {
		fatal("regain root failed")
	}

	invokerName := fmt.Sprintf("uid=%d", ruid)
	if invokerU, err := user.LookupId(fmt.Sprintf("%d", ruid)); err == nil {
		invokerName = invokerU.Username
	}

	if !rule.NoPasswd {
		if err := authenticateUser(invokerName); err != nil {
			auditLog("AUTH_FAIL", fmt.Sprintf("uid=%d target=%s", ruid, cli.TargetUser))
			time.Sleep(2 * time.Second)
			fatal("authentication failed")
		}
	} else {
		auditLog("NOPASS", fmt.Sprintf("uid=%d target=%s (nopass rule)", ruid, cli.TargetUser))
	}

	// FIX H2: only now, after authorization and authentication, open and
	// verify the binary for execution.
	fd, err := unix.Open(realCmd, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		fatal("open command failed")
	}
	vlogf("exec fd=%d opened (O_NOFOLLOW|O_CLOEXEC) for %s -> %s", fd, resolvedCmd, realCmd)

	if err := verifyTrustedBinary(fd, realCmd); err != nil {
		_ = unix.Close(fd)
		fatal("refusing to exec untrusted binary")
	}

	env := sanitizeEnv(targetU)

	if err := initGroups(cli.TargetUser, uint32(targetGID)); err != nil {
		fatal("initgroups(%q) failed", cli.TargetUser)
	}
	if err := setTargetCredentials(uint32(targetUID), uint32(targetGID)); err != nil {
		fatal("set target credentials failed")
	}

	auditLog("EXEC", fmt.Sprintf("uid=%d → target_uid=%d cmd=%s args=%q binary=%s",
				     ruid, targetUID, realCmd, cmdArgs, realCmd))

	argv := make([]string, len(cli.Args))
	copy(argv, cli.Args)
	argv[0] = cli.Command
	vlogf("execveat argv=%q", argv)

	if err := execveat(fd, "", argv, env, unix.AT_EMPTY_PATH); err != nil {
		fatal("execveat failed")
	}
}

func fatal(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintf(os.Stderr, "dau: %s\n", msg)
	auditLog("FATAL", msg)
	os.Exit(1)
}
