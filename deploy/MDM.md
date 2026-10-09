# Distributing adapter 2 (Intune / Jamf)

Adapter 2 is only an enforcement control when it is deployed as a managed
hook. An unmanaged install is advisory: a developer who can edit
`.claude/settings.json` can remove it. Tell stakeholders before anyone
counts it as a control.

## What has to land on the machine

1. A venv with forgd-verdict installed: `/opt/forgd/venv` on macOS and
   Linux, `C:\Program Files\forgd\venv` on Windows. The settings
   fragment runs the venv's interpreter, `/opt/forgd/venv/bin/python` or
   `C:\Program Files\forgd\venv\Scripts\python.exe`, as
   `python -I -X forgd_verdict_hook -m forgd_verdict.cli hook` rather than
   the `forgd-verdict` console script (`forgd-verdict.exe` on Windows),
   because a console script cannot take interpreter options. A cloned
   repository's `.claude/settings.json` `env` block sets the hook's
   environment:

   * `-I` stops Python reading `PYTHONPATH`, `PYTHONSTARTUP` and the user
     site directory from it.
   * On macOS and Linux the fragment starts the interpreter through
     `/usr/bin/env -i`, so it starts with an empty environment.
   * `-X forgd_verdict_hook` makes the package remove the variables OpenSSL
     reads, such as `OPENSSL_CONF`, `OPENSSL_MODULES`, `OPENSSL_ENGINES`,
     `SSL_CERT_FILE` and `SSL_CERT_DIR`, before hashlib and ssl load
     OpenSSL. An `OPENSSL_CONF` can load a provider library into the hook
     or name a pipe that hangs it. This is what covers Windows, where there
     is no `env -i`.

   Under `env -i`, `hook.project_overrides: true` has nothing to apply on
   macOS and Linux: the `FORGD_VERDICT_*` variables, `$VAR` placeholders,
   `FORGD_VERDICT_SPOOL`, `XDG_STATE_HOME` and `HOME` it would read from
   the environment are not there. Check the policy with the same
   interpreter:
   `/opt/forgd/venv/bin/python -I -m forgd_verdict.cli --policy /etc/forgd/policy.yaml policy`,
   or the PowerShell equivalent in
   [Verifying it is actually on](#verifying-it-is-actually-on).

   Only administrators may be able to write the venv or the base
   interpreter it runs. The venv's `pyvenv.cfg` names that interpreter's
   directory in `home =`, and the venv's `python` runs it and loads its
   standard library. A venv built on a user-installed Python (pyenv,
   `~/.local`, a uv-managed download under the user's home, a per-user
   Windows install, Homebrew, whose `/opt/homebrew` belongs to the user
   who installed it) runs code the developer can change. Build the venv
   from an interpreter the OS or an administrator installed:

   * macOS: the python.org installer's
     `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12`.
   * Linux: the distribution's `/usr/bin/python3.12`, or another
     `/usr/bin/python3.11` or later.
   * Windows: an all-users python.org install,
     `C:\Program Files\Python312\python.exe`.

   The install takes the two wheels, `hook.txt` and `SHA256SUMS` from the
   GitHub Release of the version being rolled out, and nothing from forgd
   on PyPI. `hook.txt` is `deploy/constraints/hook.txt` at that tag: the
   core's dependencies, pinned with a hash for every platform. uv runs
   from a fixed path only administrators can write, `/opt/forgd/bin/uv`
   or `C:\Program Files\forgd\bin\uv.exe`, taken from uv's GitHub release
   archive for the machine and checked against the `.sha256` published
   beside it. Neither the uv installer's default `~/.local/bin` nor
   Homebrew's uv is admin-only. Run as root, as an MDM script does, on
   macOS:

   ```bash
   set -eu
   uv=/opt/forgd/bin/uv
   repo=forgd-ai/forgd-verdict
   version=${version:?set version to the release being rolled out, such as 0.47.0}
   mkdir -p "/opt/forgd/dist/$version" && cd "/opt/forgd/dist/$version"
   for f in "forgd_verdict-$version-py3-none-any.whl" "forgd_verdict_hook-$version-py3-none-any.whl" hook.txt SHA256SUMS; do curl -fsSLO "https://github.com/$repo/releases/download/v$version/$f"; done
   shasum -a 256 -c SHA256SUMS
   awk '/\.whl$/ { split($2, p, "-"); print p[1] " @ ./" $2 " --hash=sha256:" $1 }' SHA256SUMS > forgd.txt
   "$uv" venv --no-python-downloads --python /Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12 /opt/forgd/venv
   "$uv" pip install --python /opt/forgd/venv/bin/python --require-hashes --no-build --link-mode=copy --no-cache -r hook.txt -r forgd.txt
   ```

   On Linux the venv line names the distribution's interpreter:

   ```bash
   "$uv" venv --no-python-downloads --python /usr/bin/python3.12 /opt/forgd/venv
   ```

   On Windows, as SYSTEM:

   ```powershell
   $uv = 'C:\Program Files\forgd\bin\uv.exe'
   $repo = 'forgd-ai/forgd-verdict'
   if (-not $version) { throw 'set $version to the release being rolled out, such as 0.47.0' }
   $dist = "C:\Program Files\forgd\dist\$version"
   New-Item -ItemType Directory -Force -Path $dist | Out-Null; Set-Location $dist
   foreach ($f in "forgd_verdict-$version-py3-none-any.whl", "forgd_verdict_hook-$version-py3-none-any.whl", 'hook.txt', 'SHA256SUMS') { Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/$repo/releases/download/v$version/$f" -OutFile $f }
   foreach ($line in Get-Content SHA256SUMS) { $hash, $file = $line -split '  ', 2; if ((Get-FileHash -Algorithm SHA256 $file).Hash -ne $hash) { throw "$file does not match SHA256SUMS" } }
   Get-Content SHA256SUMS | Where-Object { $_ -match '\.whl$' } | ForEach-Object { $hash, $file = $_ -split '  ', 2; "$($file.Split('-')[0]) @ ./$file --hash=sha256:$hash" } | Set-Content -Encoding ascii forgd.txt
   & $uv venv --no-python-downloads --python 'C:\Program Files\Python312\python.exe' 'C:\Program Files\forgd\venv'
   & $uv pip install --python 'C:\Program Files\forgd\venv\Scripts\python.exe' --require-hashes --no-build --link-mode=copy --no-cache -r hook.txt -r forgd.txt
   ```

   `repo` is the repository the release is cut from: a fork names its
   own. `forgd.txt` pins each wheel to its file and its hash in
   `SHA256SUMS`, because `--require-hashes` refuses a bare wheel path.
   With every requirement hashed, uv refuses an install that needs a
   package `hook.txt` does not list; `--no-deps` would install without
   it. `--no-build` refuses a source distribution, whose build would run
   as root. `--no-cache` and `--link-mode=copy` keep the venv's files from
   being links into a cache another user can write. To check where the
   wheels were built, run
   `gh attestation verify <wheel> --repo "$repo"` on each before the
   install. `--no-python-downloads` stops uv fetching a Python into the
   invoking user's directory when the named one is missing.

   cryptography publishes no wheel for Intel Macs, so `--no-build` refuses
   the install there; this release has no managed install for an Intel
   Mac.
   [Checking who can write it](#checking-who-can-write-it) confirms the
   result.
2. `policy.yaml` at a fixed path that only administrators can write:
   `/etc/forgd/policy.yaml`, root-owned, on macOS and Linux;
   `C:\ProgramData\forgd\policy.yaml` on Windows. `C:\ProgramData`
   lets members of `BUILTIN\Users` create files and folders in a new
   subdirectory by inheritance, so remove the inherited entries from
   `C:\ProgramData\forgd` before writing the policy, and grant SYSTEM and
   Administrators full control and Users read and execute.

   A developer can create `C:\ProgramData\forgd` before the MDM does. They
   then own it, and an owner can rewrite its ACL whatever icacls grants,
   or it can be a junction to a directory they control. So if the
   directory is a reparse point, is owned by anyone but Administrators or
   SYSTEM, or holds a reparse point, it is removed and recreated. A
   reparse point is removed as a link, and `rmdir /s` does not follow a
   junction inside the tree. Then Administrators take ownership of
   everything in it, the inherited entries are replaced throughout, and
   the owner is checked:

   ```powershell
   $dir = 'C:\ProgramData\forgd'
   $admins = [Security.Principal.SecurityIdentifier]'S-1-5-32-544'
   $system = [Security.Principal.SecurityIdentifier]'S-1-5-18'
   $item = Get-Item -Force -LiteralPath $dir -ErrorAction SilentlyContinue
   if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $item.Delete() }
   elseif ($item) {
     $owner = (Get-Acl -LiteralPath $dir).GetOwner([Security.Principal.SecurityIdentifier])
     $links = Get-ChildItem -LiteralPath $dir -Recurse -Force -Attributes ReparsePoint
     if (($owner -ne $admins -and $owner -ne $system) -or $links) { cmd /c rmdir /s /q "$dir" }
   }
   New-Item -ItemType Directory -Force -Path $dir | Out-Null
   icacls C:\ProgramData\forgd /setowner "*S-1-5-32-544" /T
   icacls C:\ProgramData\forgd /reset /T
   icacls C:\ProgramData\forgd /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /T
   $owner = (Get-Acl -LiteralPath $dir).GetOwner([Security.Principal.SecurityIdentifier])
   if ($owner -ne $admins) { throw "$dir is owned by $($owner.Value), not Administrators" }
   ```

   The SIDs are SYSTEM, Administrators and Users, which works whatever
   the display language. Keep the venv and gitleaks under
   `C:\Program Files\forgd`, not `C:\ProgramData`. `C:\Program Files`
   does not let Users create a directory, so a developer cannot create
   `C:\Program Files\forgd` first, and step 1, run as SYSTEM, creates it
   owned by an administrator.
   [Checking who can write it](#checking-who-can-write-it) checks the
   owner of both trees.
   Check the file before rolling it out, with the `policy` command in
   step 1 run in CI or on an admin machine on the same release, and
   require exit 0. It refuses an event in `hook.enabled_events` the hook
   does not handle, such as a misspelt one, and exits 2 with the reason on
   stderr. The hook on a laptop does not refuse it: it logs a warning,
   drops the event and scans the rest, so a typo that reaches a laptop
   leaves that event unscanned.
3. The managed settings fragment for the OS, `hooks` and
   `allowManagedHooksOnly` together: `managed-settings.fragment.json` on
   macOS and Linux, `managed-settings.windows.fragment.json` on Windows.
   The two differ in the interpreter and policy paths, in the policy
   directory their `permissions.deny` names, in the managed
   settings location their `_comment` gives, and in the macOS and Linux
   fragment starting the interpreter through `/usr/bin/env -i`. It goes in
   the
   highest-ranked managed source the organization
   deploys, or in any source if that highest one sets
   `managedSourcesBehavior: "merge"`. See
   [Precedence](#precedence-and-the-keys-that-matter).
4. `gitleaks`, for T1, at a fixed path that only administrators can write:
   `/opt/forgd/bin/gitleaks` on macOS and Linux,
   `C:\Program Files\forgd\bin\gitleaks.exe` on Windows. The shipped
   `policy.yaml` names the macOS and Linux path in the hook profile; on
   Windows set `hook.detectors.gitleaks.binary` to the `.exe` path in the
   laptop's `policy.yaml`:

   ```yaml
   hook:
     detectors:
       gitleaks:
         binary: 'C:\Program Files\forgd\bin\gitleaks.exe'
   ```

   The hook reads `hook.detectors.gitleaks` over `detectors.gitleaks`, so
   a top-level `binary` works too when the hook profile sets none.

   Install gitleaks 8.30.1, the version the images build and CI runs,
   from the gitleaks release, checking the archive against its SHA-256
   from the release's `gitleaks_8.30.1_checksums.txt`:

   | Asset | SHA-256 |
   |---|---|
   | `gitleaks_8.30.1_darwin_arm64.tar.gz` | `b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5` |
   | `gitleaks_8.30.1_darwin_x64.tar.gz` | `dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709` |
   | `gitleaks_8.30.1_linux_x64.tar.gz` | `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` |
   | `gitleaks_8.30.1_linux_arm64.tar.gz` | `e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080` |
   | `gitleaks_8.30.1_windows_x64.zip` | `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e` |

   As root on macOS and Linux, with the machine's row:

   ```bash
   set -eu
   asset=gitleaks_8.30.1_darwin_arm64.tar.gz
   sha256=b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5
   mkdir -p /opt/forgd/bin /opt/forgd/dist/gitleaks && cd /opt/forgd/dist/gitleaks
   curl -fsSLO "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/$asset"
   echo "$sha256  $asset" | shasum -a 256 -c
   tar -xzf "$asset" gitleaks
   install -o 0 -g 0 -m 0755 gitleaks /opt/forgd/bin/gitleaks
   ```

   As SYSTEM on Windows:

   ```powershell
   $asset = 'gitleaks_8.30.1_windows_x64.zip'
   $sha256 = 'd29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e'
   $dist = 'C:\Program Files\forgd\dist\gitleaks'
   New-Item -ItemType Directory -Force -Path $dist, 'C:\Program Files\forgd\bin' | Out-Null; Set-Location $dist
   Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/$asset" -OutFile $asset
   if ((Get-FileHash -Algorithm SHA256 $asset).Hash -ne $sha256) { throw "$asset does not match its SHA-256" }
   Expand-Archive -Force -Path $asset -DestinationPath $dist
   Copy-Item -Force (Join-Path $dist 'gitleaks.exe') 'C:\Program Files\forgd\bin\gitleaks.exe'
   ```

   The hook does not look gitleaks up on `PATH`, because a project's
   `.claude/settings.json` `env` sets the hook's `PATH`. With gitleaks
   enabled and no absolute `binary`, or one that does not exist, the hook
   does not run T1. It says so on stderr and in the session, then follows
   `hook.on_error`: under `block` the prompt or tool call is blocked; under
   `allow`, the shipped value, it goes through on T0 and the other
   detectors alone. A gitleaks that times out or fails during the scan is
   reported and handled the same way. `hook.project_overrides: true`
   restores the `PATH` lookup, and with it the project's choice of binary;
   under `env -i` there is no `PATH` to look in. `policy` prints
   `enabled: auto`, not whether T1 runs; step 3 of
   [Verifying it is actually on](#verifying-it-is-actually-on) confirms it.

## File locations

Verified 2026-10-04 against `code.claude.com/docs/en/managed-settings`:

| OS | Path |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux, WSL | `/etc/claude-code/managed-settings.json` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |

Claude Code does not read the legacy Windows path
`C:\ProgramData\ClaudeCode\managed-settings.json`. There is also an optional
`managed-settings.d/` drop-in directory in the same system directory, which
is the cleaner place for this fragment if you already ship other policy.

## Precedence, and the keys that matter

Managed settings sit above command line, project-local, shared-project, and
user settings. Nothing a developer sets overrides them, apart from a few
security-sensitive exceptions where a *stricter* value from a lower level
still counts.

### Which managed source applies

There can be more than one managed source on a machine. From
"How Claude Code combines managed sources" in
`code.claude.com/docs/en/managed-settings`, highest rank first:

1. Remote: server-managed settings from claude.ai or a Claude apps
   gateway, fetched only when the session authenticates to Anthropic's API
   directly.
2. MDM/OS policy: the macOS plist or HKLM.
3. Managed settings files: `managed-settings.json` plus
   `managed-settings.d/*.json`, merged together.
4. HKCU, which is not an admin source.

The default, `"first-wins"`, uses the highest-ranked source that has at
least one policy key and ignores the rest without a warning, apart from a
short list of cross-source keys. `hooks` is not one of them. A forgd hook
in `managed-settings.json` on a machine that also receives an MDM profile
or server-managed settings with any policy key does not run, and Claude
Code gives no warning; `/status` lists the file under `Skipped sources`
(Claude Code 2.1.242 or later).

So put `hooks` and `allowManagedHooksOnly` in the highest-ranked managed
source the organization deploys. Under first-wins `allowManagedHooksOnly`
is read from the selected source only, so it has to sit in the same source
as the hook.

The alternative, from "Compose every managed source", is
`managedSourcesBehavior: "merge"`. It must be set in the highest-ranked
source deployed; a lower source cannot opt itself in, so a machine that
never receives server-managed settings needs the key in its MDM profile
too. It requires Claude Code 2.1.242 or later. Under merge:

* Lists union, `hooks` included. Lower sources' `permissions.allow` rules
  and hooks join the policy, so the doc says to turn it on only when every
  source below the highest is under an administrator's control.
* `allowManagedHooksOnly` is a lock: the strictest value any source sets
  applies.

### `allowManagedHooksOnly`

The shipped fragments set `allowManagedHooksOnly: true`. Without it, hooks
from user and project settings still run alongside yours and a developer
can register their own. The first two weeks of
[the rollout order](#rollout-order-that-does-not-burn-trust) set it
`false` on purpose. Before you rely on `true`:

* Setting it `true` also disables `command` plugin sources unless
  `disableCommandPluginSources` is explicitly `false`.
* Under first-wins it counts only in the selected source, as above.

## Keeping sensitive files out of Claude's reads

The hook receives the prompt as typed. Content Claude Code attaches from an
`@` file reference, without a Read tool call, does not pass through the
hook, so adapter 2 does not scan it.

Managed `permissions.deny` rules with `Read(...)` patterns deny Claude's
file reads of the paths they match. Claude Code's permissions
documentation (`code.claude.com/docs/en/permissions`) says it makes a
best-effort attempt to apply `Read` rules to Grep and Glob, to `@file`
mentions in prompts, and to context a connected IDE shares. Best-effort is
its word, and the rule does not make adapter 2 see attached content. The
paths are your own; for example:

```json
{
  "permissions": {
    "deny": [
      "Read(.env)",
      "Read(.env.*)",
      "Read(secrets/**)"
    ]
  }
}
```

The patterns are gitignore-style and relative to the current directory: a
bare filename such as `.env` matches at any depth, and `secrets/**` in a
deny rule matches a `secrets` directory at any depth. Use `//` for an
absolute path and `~/` for one under the home directory. On Windows a path
is matched in POSIX form, so `C:\ProgramData\forgd` is
`/c/ProgramData/forgd`. A `!` carve-out in a project's or a user's
settings does not cancel a managed deny. Put the rules in the same
managed source as the hook.

The shipped fragments deny two of the hook's own paths, and the rules
go wherever the fragment is merged:

* the policy's directory, `"Read(//etc/forgd/**)"` on macOS and Linux and
  `"Read(//c/ProgramData/forgd/**)"` on Windows. The laptop's
  `policy.yaml` holds the fleet token (see
  [The fleet token](#the-fleet-token)).
* the device salt, `"Read(~/.local/state/forgd-verdict/device-salt)"`.
  With it, the hashes in that laptop's findings can be brute-forced
  over a small value space such as SSNs. A policy that sets
  `hook.spool` moves the salt to the spool's parent directory; deny that
  path instead.

The spool itself holds detector names, locators and digests, and
`hook.ca_file` is a CA certificate; neither needs a rule. These rules keep
the files out of what Claude reads. They do not stop a process the
developer runs from reading them: Users can read `policy.yaml`, the salt
is in the developer's home, and Claude Code applies `Read` rules to the
file commands it recognizes in Bash, such as `cat`, and not to a script
that opens the file itself.

## Jamf Pro (macOS)

1. Package the venv and binary. A `postinstall` that creates
   `/opt/forgd/venv` and symlinks `/usr/local/bin/forgd-verdict` is the
   least surprising shape.
2. Ship `policy.yaml` as a separate package or a Files and Processes policy,
   root-owned, `0644`.
3. Deliver the settings fragment either as a Configuration Profile
   payload or as `managed-settings.json` (or a `managed-settings.d/`
   drop-in) in a package. A Configuration Profile payload is the MDM/OS
   policy (plist) source and outranks the file, so if the organization
   already ships a Claude Code profile, the hook goes in that profile, or
   that profile sets `managedSourcesBehavior: "merge"`.
4. Scope to the developer smart group, then verify on one machine before
   widening.

## Intune (Windows / macOS)

* **Windows**: a Win32 app (`.intunewin`) that creates the venv at
  `C:\Program Files\forgd\venv`, writes `C:\ProgramData\forgd\policy.yaml`,
  and merges `managed-settings.windows.fragment.json` into
  `C:\Program Files\ClaudeCode\managed-settings.json`. Detection rule: the
  presence of `C:\Program Files\forgd\venv\Scripts\python.exe`, which is
  what the managed hook runs, plus a version check.
* **macOS**: a shell script app or a `.pkg`, plus either the managed
  settings file or a Settings Catalog / custom profile, using
  `managed-settings.fragment.json`. A profile is the plist source and
  outranks the file; the same rule as Jamf step 3 applies.

Set `command`, `--policy` and `hook.detectors.gitleaks.binary` to absolute
paths in both cases. Claude Code runs the hook with the session's environment,
including the `env` block of the project's `.claude/settings.json`, so
`PATH` is whatever the project sets.

## Checking who can write it

Run as an administrator on a target machine. On macOS and Linux:

```bash
venv=/opt/forgd/venv
home=$(sed -n 's/^home *= *//p' "$venv/pyvenv.cfg")
stdlib=$("$venv/bin/python" -I -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')
cat "$venv/pyvenv.cfg"
ls -ld /opt/forgd "$venv" "$home" "$stdlib" /opt/forgd/bin /opt/forgd/bin/gitleaks /opt/forgd/bin/uv /etc/forgd /etc/forgd/policy.yaml
ls -lL "$venv/bin/python"
# expect: every line owned by root, with no `w` in the other column, and
# a `w` in the group column only for group root or wheel (gid 0), as the
# python.org framework installs. `home` must not be under a user's home
# directory.
find "$venv" "$home" "$stdlib" /opt/forgd/bin /etc/forgd ! -type l \( ! -user root -o \( -perm -g=w ! -group 0 \) -o -perm -o=w \) -print
# expect: no output.
```

On Windows, in PowerShell:

```powershell
Get-Content 'C:\Program Files\forgd\venv\pyvenv.cfg'
foreach ($p in 'C:\Program Files\forgd', 'C:\ProgramData\forgd') { @(Get-Item -Force -LiteralPath $p) + @(Get-ChildItem -Force -Recurse -LiteralPath $p) | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ((Get-Acl -LiteralPath $_.FullName).GetOwner([Security.Principal.SecurityIdentifier]).Value -notin 'S-1-5-32-544', 'S-1-5-18') } | ForEach-Object FullName }
# expect: no output. Each path printed is a link or has an owner other
# than Administrators or SYSTEM, and its owner can change its ACL.
icacls 'C:\Program Files\forgd' /T
# /T lists bin\uv.exe and bin\gitleaks.exe with the venv.
icacls C:\ProgramData\forgd /T
# Then icacls on the directory pyvenv.cfg names in `home =`.
```

Every entry should be `NT AUTHORITY\SYSTEM` or `BUILTIN\Administrators`
with `(F)`, or `BUILTIN\Users` with `(RX)`, plus `TrustedInstaller` and
the `APPLICATION PACKAGE AUTHORITY` read entries on a directory under
`C:\Program Files`. Any `(W)`, `(M)`, `(F)`, `(AD)` or `(WD)` for
`BUILTIN\Users`, `Authenticated Users`, `Everyone`, `CREATOR OWNER` or a
named user means a developer can change what the hook runs or reads.

## What the hook cannot protect against

A project's `.claude/settings.json` `env` block reaches the hook's
environment. `env -i` on macOS and Linux and the `-X forgd_verdict_hook`
scrub on Windows (step 1 above) keep it from the variables the hook and
OpenSSL read once Python is running. Some act before that:

* `LD_PRELOAD` and `LD_LIBRARY_PATH` on Linux are read by the dynamic
  loader when Claude Code starts `/usr/bin/env`, before `env -i` clears
  them, so they can load a library into that process. On macOS, SIP
  removes `DYLD_*` variables such as `DYLD_INSERT_LIBRARIES` when
  `/usr/bin/env` starts; with SIP off they reach it. They reach the
  `hook-ship` drain the same way. Endpoint controls on the machine are the
  place to address them.
* On Windows, `PYTHONEXECUTABLE` chooses which `pyvenv.cfg` and which
  `.pth` files Python runs before the hook's first statement, even under
  `-I`.
* On Windows the hook's home directory comes from `USERPROFILE`. It
  decides where the default spool and the device salt live, so a project
  can move both. Set an absolute `hook.spool` in the policy to place them.

The full list, with what the hook does withstand and which controls a
laptop cannot affect, is in
[SECURITY-MODEL.md § The Claude Code hook's threat model](../docs/SECURITY-MODEL.md#the-claude-code-hooks-threat-model).

## Verifying it is actually on

On a target machine:

```bash
# 1. The policy the hook will use, with secrets redacted. It prints
#    gitleaks as `enabled: auto`, not whether T1 runs; step 3 checks that.
/opt/forgd/venv/bin/python -I -m forgd_verdict.cli --policy /etc/forgd/policy.yaml policy

# A throwaway spool, so these test findings are never shipped to the store.
# The device salt goes in its parent, the mktemp directory.
spool="$(mktemp -d)/spool"

# 2. The hook itself, end to end, run as the managed settings run it, plus
#    --spool.
echo '{"hook_event_name":"UserPromptSubmit","prompt":"key AKIAQYLPMN5HGZTHX4UQ"}' \
  | /usr/bin/env -i /opt/forgd/venv/bin/python -I -X forgd_verdict_hook -m forgd_verdict.cli hook --policy /etc/forgd/policy.yaml --spool "$spool"
# expect: {"decision":"block","reason":"..."}
#
# UserPromptSubmit blocks on a top-level `decision`. PreToolUse is the event
# that uses hookSpecificOutput.permissionDecision:
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo AKIAQYLPMN5HGZTHX4UQ"}}' \
  | /usr/bin/env -i /opt/forgd/venv/bin/python -I -X forgd_verdict_hook -m forgd_verdict.cli hook --policy /etc/forgd/policy.yaml --spool "$spool"
# expect: {"hookSpecificOutput":{...,"permissionDecision":"deny",...}}

# 3. T1. A GitLab token, which gitleaks detects and T0 does not, assembled
#    from two parts so this file holds no literal one.
printf '{"hook_event_name":"UserPromptSubmit","prompt":"token %s%s"}' 'glpat-' 'V9v0M48onQvilZzFz0tS' \
  | /usr/bin/env -i /opt/forgd/venv/bin/python -I -X forgd_verdict_hook -m forgd_verdict.cli hook --policy /etc/forgd/policy.yaml --spool "$spool"
# expect: {"decision":"block","reason":"... a GitLab credential ..."}
# A systemMessage that gitleaks (T1) did not run, or no output, means T1 is
# off on this machine: see step 4 of "What has to land on the machine".
```

The same three steps on Windows, in PowerShell:

```powershell
# 1. The policy the hook will use, with secrets redacted.
& 'C:\Program Files\forgd\venv\Scripts\python.exe' -I -m forgd_verdict.cli --policy C:\ProgramData\forgd\policy.yaml policy

# A throwaway spool, so these test findings are never shipped to the store.
# The device salt goes in its parent.
$spoolDir = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([guid]::NewGuid()))
$spool = Join-Path $spoolDir.FullName 'spool'

# 2. The hook itself, run as the managed settings run it, plus --spool.
'{"hook_event_name":"UserPromptSubmit","prompt":"key AKIAQYLPMN5HGZTHX4UQ"}' | & 'C:\Program Files\forgd\venv\Scripts\python.exe' -I -X forgd_verdict_hook -m forgd_verdict.cli hook --policy C:\ProgramData\forgd\policy.yaml --spool $spool
# expect: {"decision":"block","reason":"..."}
'{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo AKIAQYLPMN5HGZTHX4UQ"}}' | & 'C:\Program Files\forgd\venv\Scripts\python.exe' -I -X forgd_verdict_hook -m forgd_verdict.cli hook --policy C:\ProgramData\forgd\policy.yaml --spool $spool
# expect: {"hookSpecificOutput":{...,"permissionDecision":"deny",...}}

# 3. T1, with the GitLab token assembled from two parts as above.
('{"hook_event_name":"UserPromptSubmit","prompt":"token ' + 'glpat-' + 'V9v0M48onQvilZzFz0tS' + '"}') | & 'C:\Program Files\forgd\venv\Scripts\python.exe' -I -X forgd_verdict_hook -m forgd_verdict.cli hook --policy C:\ProgramData\forgd\policy.yaml --spool $spool
# expect: {"decision":"block","reason":"... a GitLab credential ..."}
# A systemMessage that gitleaks (T1) did not run, or no output, means T1 is
# off on this machine: see step 4 of "What has to land on the machine".

Remove-Item -Recurse $spoolDir
```

Then Claude Code's own view, in a session on the same machine
("Read the source in /status"):

* `/status`: the `Setting sources` line shows
  `Enterprise managed settings (...)` naming the source applied (`remote`,
  `plist`, `HKLM`, `file`, `drop-ins`, `file + drop-ins`, ...), with
  `, merged` when `managedSourcesBehavior` is `"merge"`. A
  `Skipped sources` line names the sources found and not selected
  (2.1.242 or later). The source carrying the forgd hook must be the one
  applied, or merge must be on.
* `/hooks`: every event lists the forgd hook, `UserPromptExpansion`
  included.

If step 2 denies but Claude Code never blocks, start with `/status`: a
forgd source listed under `Skipped sources` means a higher-ranked source
won, and the hook belongs there (or that source needs
`managedSourcesBehavior: "merge"`). If the right source is applied and
`/hooks` does not list the hook, check the managed settings path for the
OS, and that the JSON parses.

## The fleet token

A laptop that ships to the intake (`hook.ship_endpoint`) or asks it for a
verdict (`hook.scan_endpoint`) authenticates with its fleet's bearer token:
`intake.fleet[].tokens` on the intake service, and `hook.ship_token` and
`hook.scan_token` in each laptop's `policy.yaml`. Every laptop in the fleet
holds the same value. The hook does not read the project's environment, so
MDM writes the value into the policy file rather than a `$VAR`.

Anyone who can read that file can read the token. It lets them append
records to the intake and ask `/scan` for verdicts, and nothing else: the
intake has no read path. Revocation is by device, below, or by rotation.

Each laptop names itself in the `X-Forgd-Device` header. The hook sends its
device salt's namespace, `d` and 12 hex characters, which is also the
`salt_namespace` on every record it spools. The salt is the file
[provisioned below](#provisioning-the-device-salt), or without one a file
in the user's home directory. A fleet request with no header, or one in
any other form, a machine name for instance, is refused with 403
`device_required` and counted as `device_missing`, so no person's name is
stored; `intake.fleet[].require_device: false` accepts it instead. The id
is shown under each row's surface in the Event Log, and the Event Log
filters on it.

One fleet can serve developers in several orgs, prod, dev and a Team
workspace for instance, with `intake.fleet[].orgs` listing them
([docs/POLICY.md](../docs/POLICY.md#a-fleet-whose-developers-work-in-several-orgs)).
The laptop's records are then attributed to an org through Claude Code's
own OTel export, so push the OTel settings (`OTEL_*` and the collector
token) in the same profile as the fleet token. A laptop without them still
scans and ships; its records show as org pending, visible only to viewers
of every org in the fleet.

### Distributing it

1. Generate the token. Never choose one:

   ```sh
   python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
   ```

2. Give it to the intake service as `FORGD_INTAKE_FLEET_TOKEN`. Under the
   Helm chart, set `intake.fleet.enabled: true` and put the value in the
   release's secret under the key `intake-fleet-token`
   (`secrets.intakeFleetToken`, or that key in `secrets.existingSecret`).
   The shipped `policy.yaml` reads it in `intake.fleet`.

3. Write it into the laptop policy through MDM, beside the endpoints:

   ```yaml
   hook:
     ship_endpoint: https://intake.example.com/intake
     ship_token: <the fleet token>
     scan_endpoint: https://intake.example.com/scan
     scan_token: <the fleet token>
   ```

### Rotating it

The intake accepts two tokens at once, so laptops move over at MDM's pace
and none is refused in between.

1. Generate a new token. Move the current value to
   `FORGD_INTAKE_FLEET_TOKEN_PREVIOUS` (Helm key
   `intake-fleet-token-previous`), set the new one as
   `FORGD_INTAKE_FLEET_TOKEN`, and roll the intake. The shipped policy lists
   both variables; an unset one is skipped.
2. Push the new token to every laptop's `policy.yaml` through MDM, and
   wait until MDM reports the profile installed fleet-wide.
3. Remove `FORGD_INTAKE_FLEET_TOKEN_PREVIOUS` and roll the intake again.
   A laptop still on the old token gets 401: it parks the batches it could
   not ship and retries them, and `/scan` falls back to a local scan, until
   MDM reaches it.
4. Clear the device denylist, `forgd-verdict overrides clear-devices`. A
   device denied before the rotation no longer holds a token; deny again
   any that MDM still manages and that should stay cut off.

### Provisioning the device salt

Without it, the device salt is a file in the user's home directory, and
deleting it gives the laptop a new device id: a denied laptop comes back
as a new device whenever its user wants. Provision one per machine that
the user cannot rewrite, and name it in the laptop policy:

```yaml
hook:
  device_salt_path: /etc/forgd/device-salt      # C:\ProgramData\forgd\device-salt on Windows
```

It is read from the policy file only, never from the environment. Write
it once, when the machine is enrolled, and never again: a new salt is a
new device id.

macOS and Linux, as root:

```sh
[ -s /etc/forgd/device-salt ] || {
  umask 022
  /opt/forgd/venv/bin/python -I -c 'import secrets; print(secrets.token_hex(32))' \
    > /etc/forgd/device-salt
}
chown root /etc/forgd/device-salt
chmod 0444 /etc/forgd/device-salt
```

`/etc/forgd` itself must be root-owned and not group- or world-writable,
as it already is for `policy.yaml`.

Windows, as SYSTEM, after `C:\ProgramData\forgd` has the ACL from
[What has to land on the machine](#what-has-to-land-on-the-machine):

```powershell
$path = 'C:\ProgramData\forgd\device-salt'
if (-not (Test-Path $path) -or (Get-Item $path).Length -eq 0) {
  $bytes = New-Object byte[] 32
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  Set-Content -Path $path -Encoding ascii -Value (-join ($bytes | ForEach-Object { $_.ToString('x2') }))
}
icacls $path /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" "*S-1-5-32-545:R"
```

On macOS and Linux the hook refuses the file when it is a symlink, not 64
hex characters, owned by the user running the hook, writable by them, its
group or others, or in a directory they, its group or others can write. On
Windows it checks the content only, and the ACL above is what keeps users
out. A refused file sends no device id, said on stderr, so the intake
refuses that laptop's requests with `device_required` until the file is
fixed. Shipping parks and retries, and `/scan` falls back to a local scan.

### Reporting the id to inventory

`forgd-verdict hook device-id` prints the id the hook sends, and exits
non-zero when it would send none. Report it into inventory, so a laptop
can be found by serial number.

Jamf Pro extension attribute (it runs as root, and reads the provisioned
salt, so set `hook.device_salt_path` first; without it the id printed is
root's own, not the developer's):

```sh
#!/bin/sh
id=$(/opt/forgd/venv/bin/python -I -m forgd_verdict.cli \
  --policy /etc/forgd/policy.yaml hook device-id 2>/dev/null)
echo "<result>${id:-none}</result>"
```

Intune, as the detection script of a Remediation, whose output the
device's Remediations report shows:

```powershell
$id = & 'C:\Program Files\forgd\venv\Scripts\python.exe' -I -m forgd_verdict.cli --policy C:\ProgramData\forgd\policy.yaml hook device-id 2>$null
if ($LASTEXITCODE -eq 0) { Write-Output $id; exit 0 }
Write-Output 'none'; exit 1
```

### Revoking one device

Look the laptop up by serial number in Jamf or Intune and read its device
id from the inventory attribute above, then deny that id. It takes runtime
overrides ([docs/OVERRIDES.md](../docs/OVERRIDES.md)):

```sh
forgd-verdict overrides deny-device d0123456789ab
```

or, as a dashboard admin, **deny device** on one of its rows in the Event
Log; `/events?device=<id>` lists that laptop's rows for the window on the
first page. Each intake replica picks the change up within a minute and answers
that device with 403 on both routes, counted as `device_denied` in
`/stats`. `undeny-device` and `clear-devices` reverse it. Upgrade every
intake replica before denying a device: a replica older than the denylist
does not adopt the overrides object at all.

The device id is the laptop's own claim. With the provisioned salt, a
denied laptop running the managed hook stays cut off, whoever signs in.
With the per-user salt, its user can delete the file and come back as a
new device, so denying holds only for a user who cooperates. Either way,
every developer on a managed laptop can read the fleet token: the hook
runs as them and reads it from `policy.yaml`, which is `0644`. Anyone who
has copied it can send any device id, so a denied id does not stop them.
When the token itself may have been taken, rotate it, then clear the
denylist as in step 4 of [Rotating it](#rotating-it).

With runtime overrides off, the intake warns at startup that a device
cannot be denied, and a fleet-wide rotation is the only way to cut one off.

## Rollout order that does not burn trust

The shipped `policy.yaml` and managed settings fragments are the end state
of step 3: `t0_regex` and `gitleaks` at `block`, and
`"allowManagedHooksOnly": true`. Deployed unchanged on macOS or Linux, with
gitleaks at `/opt/forgd/bin/gitleaks` as step 4 of
[What has to land on the machine](#what-has-to-land-on-the-machine) says,
they enforce from the first prompt. On Windows the policy also needs the
`.exe` path in `hook.detectors.gitleaks.binary`; without it T1 does not
run. Steps 1 and 2 relax them on purpose, so the first false positive is
not also the first time anyone has heard of the tool.

While `allowManagedHooksOnly` is `false`, in steps 1 and 2, a developer can
switch the hook off from their own settings. That is a deliberate,
time-boxed relaxation. Give it an end date, and do not count adapter 2 as a
control until step 3 is deployed.

1. **One week, T0 only.** Turn gitleaks off in `policy.yaml`. `t0_regex`
   stays at `block`. `shell_exfil` ships at `warn` and never blocks, so it
   can stay on. `presidio_pii` and `llmguard_pii` ship off.

   ```yaml
   detectors:
     gitleaks:
       enabled: false
   ```

   In the fragment for the OS (`managed-settings.fragment.json` or
   `managed-settings.windows.fragment.json`):

   ```json
   "allowManagedHooksOnly": false
   ```

2. **gitleaks at `warn`.** Turn gitleaks back on without blocking and read
   what it would have blocked. Leave `"allowManagedHooksOnly": false`.

   ```yaml
   detectors:
     gitleaks:
       enabled: auto
       severity: warn
   ```

3. **Lock.** Once the false-positive rate is known, put back the shipped
   values: gitleaks at `block`, and `"allowManagedHooksOnly": true` in the
   fragment.

   ```yaml
   detectors:
     gitleaks:
       enabled: auto
       severity: block
   ```

   ```json
   "allowManagedHooksOnly": true
   ```
