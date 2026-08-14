package main

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const confPath = "/etc/dau.conf"

type argsMode int

const (
	argsEmpty argsMode = iota
	argsAny
	argsExact
)

type Rule struct {
	NoPasswd bool
	Identity string
	Target   string
	Command  string
	Args     argsMode
	ArgSpec  []string
}

type Config struct{ Rules []Rule }

func loadConfig() *Config {
	vlogf("config: opening %s (O_RDONLY|O_NOFOLLOW|O_CLOEXEC)", confPath)
	f, err := os.OpenFile(confPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		fatal("config: open: %v", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		fatal("config: fstat: %v", err)
	}
	vlogf("config: fstat mode=%o regular=%v", fi.Mode().Perm(), fi.Mode().IsRegular())
	if !fi.Mode().IsRegular() {
		fatal("config: %s is not a regular file", confPath)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		fatal("config: cannot obtain syscall.Stat_t")
	}
	vlogf("config: owner uid=%d gid=%d", st.Uid, st.Gid)
	if st.Uid != 0 || st.Gid != 0 {
		fatal("config: %s must be owned root:root (got %d:%d)", confPath, st.Uid, st.Gid)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		fatal("config: %s has mode %04o; must be strictly 0600", confPath, perm)
	}

	cfg := &Config{}
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule, err := parseRule(line)
		if err != nil {
			fatal("config: line %d: %v", lineNo, err)
		}
		vlogf("config: line %d parsed → nopass=%v identity=%s target=%s cmd=%q args=%v spec=%v",
			lineNo, rule.NoPasswd, rule.Identity, rule.Target, rule.Command, rule.Args, rule.ArgSpec)
		if rule.Command == "" || rule.Args == argsAny {
			auditLog("POLICY_WARN", fmt.Sprintf("line %d: unrestricted rule", lineNo))
			vlogf("config: unrestricted rule detail identity=%s target=%s cmd=%q args=%v",
			      rule.Identity, rule.Target, rule.Command, rule.Args)
		}
		cfg.Rules = append(cfg.Rules, rule)
	}
	if err := scanner.Err(); err != nil {
		fatal("config: read: %v", err)
	}
	return cfg
}

func parseRule(line string) (Rule, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return Rule{}, fmt.Errorf("empty rule")
	}
	if fields[0] != "permit" {
		return Rule{}, fmt.Errorf("unknown keyword %q", fields[0])
	}
	fields = fields[1:]
	r := Rule{Target: "root", Args: argsEmpty}
	i := 0

	if i < len(fields) && fields[i] == "nopass" {
		r.NoPasswd = true
		i++
	}
	if i >= len(fields) {
		return Rule{}, fmt.Errorf("missing identity")
	}
	r.Identity = fields[i]
	i++

	if i < len(fields) && fields[i] == "as" {
		i++
		if i >= len(fields) {
			return Rule{}, fmt.Errorf("missing target after \"as\"")
		}
		r.Target = fields[i]
		i++
	}
	if i < len(fields) && fields[i] == "cmd" {
		i++
		if i >= len(fields) {
			return Rule{}, fmt.Errorf("missing command after \"cmd\"")
		}
		if !filepath.IsAbs(fields[i]) {
			return Rule{}, fmt.Errorf("command %q must be absolute", fields[i])
		}
		r.Command = fields[i]
		i++
	}
	if i < len(fields) && fields[i] == "args" {
		i++
		if r.Command == "" {
			return Rule{}, fmt.Errorf("args requires cmd")
		}
		if i >= len(fields) {
			return Rule{}, fmt.Errorf("missing spec after \"args\"")
		}
		if fields[i] == "any" {
			r.Args = argsAny
			i++
		} else {
			r.Args = argsExact
			r.ArgSpec = append([]string(nil), fields[i:]...)
			i = len(fields)
		}
	}
	if i < len(fields) {
		return Rule{}, fmt.Errorf("trailing token %q", fields[i])
	}
	return r, nil
}

func matchArgSpec(spec, got []string) bool {
	if len(spec) != len(got) {
		return false
	}
	for i := range spec {
		if spec[i] == got[i] {
			continue
		}
		ok, err := path.Match(spec[i], got[i])
		if err != nil || !ok {
			return false
		}
	}
	return true
}

func matchRule(rule Rule, invokerUID uint32, invokerGIDs []uint32,
	targetUser, command string, cmdArgs []string) (bool, string) {

	if rule.Target != targetUser {
		return false, fmt.Sprintf("target %q != %q", rule.Target, targetUser)
	}
	if rule.Command != "" {
		if rule.Command != command {
			return false, fmt.Sprintf("cmd %q != %q", rule.Command, command)
		}
		switch rule.Args {
		case argsEmpty:
			if len(cmdArgs) != 0 {
				return false, fmt.Sprintf("args must be empty, got %v", cmdArgs)
			}
		case argsAny:
		case argsExact:
			if !matchArgSpec(rule.ArgSpec, cmdArgs) {
				return false, fmt.Sprintf("args %v !~ spec %v", cmdArgs, rule.ArgSpec)
			}
		}
	}
	if strings.HasPrefix(rule.Identity, "@") {
		g, err := user.LookupGroup(rule.Identity[1:])
		if err != nil {
			return false, fmt.Sprintf("group %q lookup failed", rule.Identity)
		}
		gid, err := strconv.ParseUint(g.Gid, 10, 32)
		if err != nil {
			return false, "malformed group gid (fail closed)"
		}
		for _, id := range invokerGIDs {
			if uint32(gid) == id {
				return true, ""
			}
		}
		return false, fmt.Sprintf("invoker not in group %q", rule.Identity)
	}
	u, err := user.Lookup(rule.Identity)
	if err != nil {
		return false, fmt.Sprintf("user %q lookup failed", rule.Identity)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return false, "malformed user uid (fail closed)"
	}
	if uint32(uid) != invokerUID {
		return false, fmt.Sprintf("identity uid %d != invoker uid %d", uid, invokerUID)
	}
	return true, ""
}

func (c *Config) findRule(invokerUID uint32, invokerGIDs []uint32,
	targetUser, command string, cmdArgs []string) *Rule {
	for i := range c.Rules {
		ok, reason := matchRule(c.Rules[i], invokerUID, invokerGIDs, targetUser, command, cmdArgs)
		if ok {
			vlogf("rule[%d] MATCH", i)
			return &c.Rules[i]
		}
		vlogf("rule[%d] no match: %s", i, reason)
	}
	return nil
}
