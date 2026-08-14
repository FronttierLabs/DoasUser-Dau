# dau — do as user

A minimal, PAM-backed privilege-escalation utility for Linux, written in Go + CGO.
Think of it as a tiny, auditable `sudo`/`doas` alternative.

Current release: `v1.2.0-kestrel`

## Features
- PAM authentication against the `dau` service (fail-closed, no silent fallback)
- setuid-root with careful privilege drop / re-acquire (`setresuid`)
- Argument-restricted policy rules (`permit … cmd … args …`)
- TOCTOU-safe exec via `execveat(AT_EMPTY_PATH)` on an `O_NOFOLLOW` fd
- Hardened child env (hardcoded `safePATH`, LANG/TERM allowlists; nothing inherited)
- Config hardening: root:root 0600 only, `O_NOFOLLOW` + `fstat` (no TOCTOU/symlink)
- Full audit trail to `LOG_AUTHPRIV` syslog
- Exhaustive `-v` trace for debugging

## Install (as root)

There is intentionally no installer script — the steps below ARE the installer.
Run everything as root or with sudo for each commands.

### Debian / Ubuntu (tested on Debian 13 and works)

```bash
doas/sudo apt-get update
doas/sudo apt-get install -y --no-install-recommends build-essential golang-go libpam0g-dev git
git clone https://github.com/FronttierLabs/Dau-DoasUser.git
cd Dau-DoasUser
export CGO_ENABLED=1
export CGO_CFLAGS="-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong"
go build -buildmode=pie -o dau -ldflags '-s -w' .
install -m 4755 -o root -g root ./dau /usr/local/bin/dau
install -m 0600 -o root -g root examples/dau.conf /etc/dau.conf
printf '#%%PAM-1.0\nauth      include     common-auth\naccount   include     common-account\n' > /etc/pam.d/dau
chmod 0644 /etc/pam.d/dau

!!NEEDED!! 
cd..
rm-rf Dau-DoasUser
```

### Arch Linux (tested on Cachy Os 99% sure works on base arch)

```bash
doas/sudo pacman -Sy --noconfirm base-devel go git
git clone https://github.com/FronttierLabs/Dau-DoasUser.git
cd Dau-DoasUser
export CGO_ENABLED=1
export CGO_CFLAGS="-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong"
go build -buildmode=pie -o dau -ldflags '-s -w' .
install -m 4755 -o root -g root ./dau /usr/local/bin/dau
install -m 0600 -o root -g root examples/dau.conf /etc/dau.conf
printf '#%%PAM-1.0\nauth      include     system-auth\naccount   include     system-auth\n' > /etc/pam.d/dau
chmod 0644 /etc/pam.d/dau

!!NEEDED!! 
cd..
rm-rf Dau-DoasUser

```
### Void (tested on Void and works)

```bash
sudo/doas xbps-install -Sy base-devel go git pam pam-devel
git clone https://github.com/FronttierLabs/Dau-DoasUser.git
cd Dau-DoasUser
export CGO_ENABLED=1
export CGO_CFLAGS="-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong"
go build -buildmode=pie -o dau -ldflags '-s -w' .
install -m 4755 -o root -g root ./dau /usr/local/bin/dau
install -m 0600 -o root -g root examples/dau.conf /etc/dau.conf
printf '#%%PAM-1.0\nauth      include     system-auth\naccount   include     system-auth\n' > /etc/pam.d/dau
chmod 0644 /etc/pam.d/dau

!!NEEDED! 
cd..
rm-rf Dau-DoasUser

```



### Post-install (both distros)

- Edit `/etc/dau.conf` to your policy. It must stay `0600 root:root` or `dau` refuses to read it.
  - Arch: `permit @wheel as root` (wheel exists)
  - Debian: `permit @sudo as root` (Debian uses the sudo group, not wheel)
- On live ISOs: set a password for the invoking user first (`passwd`); PAM needs one.
- Verify: `dau -version` and `dau id`.

### Symlinked binaries (e.g., reboot, vi)

`dau` resolves symlinks to their real targets (e.g., `/sbin/reboot` → `/bin/systemctl`)
before opening the file descriptor. Security is maintained by strictly verifying that the
directory containing the *final* resolved binary is also root-owned and non-writable.

## Policy (`/etc/dau.conf`)

```
permit @wheel as root                                   # blanket (logged as risk)
permit alice as root cmd /usr/bin/systemctl args restart -- nginx
permit bob as root cmd /usr/bin/journalctl args -*
permit carol as root cmd /usr/bin/less args any         # explicit opt-in
```

## Security model (MUST READ!!!)

- **Trusted-binary invariant:** every executed binary must be root-owned, not
  group/other-writable, and live in a root-owned, non-writable directory.
- **No path fallback:** exec is strictly `execveat(AT_EMPTY_PATH)` on an
  `O_NOFOLLOW` fd; a path fallback would re-open the TOCTOU race.
- **No interactive shell:** `dau` with no command fails closed (`no command specified`).
- **Auth lifecycle:** authenticate + account only. No PAM cred or session management
  (dau execs directly and cannot close a session after the fact).
- **Rate limiting:** the 2s failure delay is only a speed-bump; real lockout
  must come from `pam_faillock` (or equivalent) in your PAM stack.
- **`-v` is for debugging only**; never enable it in production.
- The policy file is read as root by design (it is 0600 root:root).

## SOME USE OF AI Models where used in the creation of DAU/DoasUser
```bash
used Depseek v4 Flash/claude fable5/opus5/qwen3.8MAX for security auditing i used some of the AI advice to fix the security issues and not ask them for fixes
!!!YES I MOSTLY USED AI TO REGERATE THE README!!!


```