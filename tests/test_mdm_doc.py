"""deploy/MDM.md: managed-source precedence and the verification commands."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
MDM = (ROOT / "deploy" / "MDM.md").read_text()


def _scan_hook_argv(name: str) -> list[str]:
    """The fragment's UserPromptSubmit command line."""
    fragment = json.loads((ROOT / "deploy" / name).read_text())
    [entry] = fragment["hooks"]["UserPromptSubmit"]
    [hook] = entry["hooks"]
    return [hook["command"], *hook["args"]]


# What the fragment runs, which every probe in MDM.md must run too.
MANAGED = " ".join(_scan_hook_argv("managed-settings.fragment.json"))


def _bash_commands() -> list[str]:
    """Each non-comment command in MDM.md's bash blocks, continuations joined."""
    commands: list[str] = []
    for block in re.findall(r"```bash\n(.*?)```", MDM, re.S):
        joined = re.sub(r"\\\n\s*", " ", block)
        for line in joined.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                commands.append(line)
    return commands


def _hook_invocations() -> list[str]:
    return [c for c in _bash_commands()
            if re.search(r"(forgd-verdict|forgd_verdict\.cli)\s+hook\b", c)]


def test_mdm_names_the_managed_sources_key_and_status():
    assert "managedSourcesBehavior" in MDM
    assert "/status" in MDM


def test_mdm_no_longer_describes_a_default_merge():
    assert "default merge behaviour" not in MDM


def test_no_bash_block_pipes_into_the_console_script_hook():
    assert not [c for c in _bash_commands() if re.search(r"\|\s*forgd-verdict\s+hook\b", c)]


def test_every_hook_invocation_is_the_exact_managed_command():
    invocations = _hook_invocations()
    assert invocations
    assert [c for c in invocations if MANAGED not in c] == []


# --- `@` file references and managed Read deny rules ------------------------------

FRAGMENT = ROOT / "deploy" / "managed-settings.fragment.json"


def _flat(text: str) -> str:
    return " ".join(text.split())


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    end = text.find("\n## ", start + 1)
    return text[start:end if end != -1 else len(text)]


DISCLOSED_IN = {
    "README.md": lambda t: t,
    "docs/SECURITY-MODEL.md": lambda t: t,
    "docs/PLATFORM.md": lambda t: _section(t, "## Adapter 2"),
}


@pytest.mark.parametrize("path", sorted(DISCLOSED_IN))
def test_the_at_file_gap_is_disclosed(path):
    """Content attached from an `@` file reference does not pass through
    the hook, so adapter 2 does not scan it."""
    text = _flat(DISCLOSED_IN[path]((ROOT / path).read_text(encoding="utf-8")))
    assert re.search(r"`@` file reference", text), path
    assert "Read(" in text or "permissions.deny" in text, path


def test_mdm_shows_a_managed_read_deny_rule():
    text = _flat(MDM)
    assert "permissions.deny" in text
    assert re.search(r"\"Read\((\.env|\.env\.\*|secrets/\*\*)\)\"", MDM)


def test_the_fragment_comment_points_at_read_deny_rules():
    comment = " ".join(json.loads(FRAGMENT.read_text())["_comment"])
    assert "permissions.deny" in comment and "Read(" in comment
    deny = json.loads(FRAGMENT.read_text())["permissions"]["deny"]
    assert not [r for r in deny if ".env" in r or "secrets" in r], deny


MANAGED_POLICY = "/opt/forgd/venv/bin/python -I -m forgd_verdict.cli --policy /etc/forgd/policy.yaml policy"


def test_mdm_checks_the_policy_with_the_managed_command():
    assert "forgd-verdict policy" not in MDM
    assert "forgd-verdict --policy" not in MDM
    assert MANAGED_POLICY in _bash_commands()


def test_mdm_confirms_t1_with_a_hook_run_into_a_throwaway_spool():
    """`policy` prints `enabled: auto`, not whether gitleaks runs."""
    t1 = [c for c in _bash_commands() if "glpat-" in c and MANAGED in c]
    assert t1, "no T1 check through the managed hook command"
    assert all("--spool" in c for c in t1), t1


def test_no_probe_names_the_spool_through_the_environment():
    """The hook ignores FORGD_VERDICT_SPOOL without project overrides, so a
    probe that sets it writes into the real spool and the next ship sends
    the test findings to the store."""
    probes = _bash_commands() + _powershell_commands()
    assert [c for c in probes if "FORGD_VERDICT_SPOOL" in c] == []


def test_every_hook_probe_passes_a_throwaway_spool():
    bash = _hook_invocations()
    powershell = [c for c in _powershell_commands() if re.search(r"forgd_verdict\.cli\s+hook\b", c)]
    assert bash and powershell
    assert [c for c in bash if not re.search(r'--spool "\$spool"', c)] == []
    assert [c for c in powershell if not re.search(r"--spool \$spool\b", c)] == []
    assert any(re.match(r'spool="\$\(mktemp -d\)/spool"', c) for c in _bash_commands())


# --- gitleaks on the laptop -----------------------------------------------------------

LANDS = _section(MDM, "## What has to land on the machine")


def test_step_4_installs_gitleaks_at_an_admin_path_named_by_the_policy():
    step4 = _flat(LANDS[LANDS.index("\n4. "):])
    assert "detectors.gitleaks.binary" in step4
    assert "/opt/forgd/bin/gitleaks" in step4
    assert r"C:\Program Files\forgd\bin\gitleaks.exe" in step4
    assert "on `PATH` for T1" not in step4
    assert "hook.on_error" in step4 and "systemMessage" not in step4


def test_mdm_does_not_say_the_hook_gets_an_mdm_path():
    """Claude Code runs the hook with the session's environment, a
    project's `.claude/settings.json` `env` included."""
    text = _flat(MDM)
    assert "is not the developer's interactive `PATH`" not in text
    intune = _flat(_section(MDM, "## Intune"))
    assert "`.claude/settings.json`" in intune and "`env`" in intune


# --- Windows -----------------------------------------------------------------------

WINDOWS_PYTHON = r"& 'C:\Program Files\forgd\venv\Scripts\python.exe' -I -m forgd_verdict.cli"
_WINDOWS_ARGV = _scan_hook_argv("managed-settings.windows.fragment.json")
WINDOWS_MANAGED = f"& '{_WINDOWS_ARGV[0]}' " + " ".join(_WINDOWS_ARGV[1:])
WINDOWS_MANAGED_POLICY = WINDOWS_PYTHON + r" --policy C:\ProgramData\forgd\policy.yaml policy"


def _powershell_commands() -> list[str]:
    """Each non-comment line in MDM.md's powershell blocks, backtick continuations joined."""
    commands: list[str] = []
    for block in re.findall(r"```powershell\n(.*?)```", MDM, re.S):
        joined = re.sub(r"`\n\s*", " ", block)
        for line in joined.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                commands.append(line)
    return commands


def test_mdm_verifies_windows_with_the_windows_managed_command():
    commands = _powershell_commands()
    assert WINDOWS_MANAGED_POLICY in commands
    invocations = [c for c in commands if re.search(r"forgd_verdict\.cli\s+hook\b", c)]
    assert len(invocations) >= 3, invocations
    assert [c for c in invocations if WINDOWS_MANAGED not in c] == []


def test_the_windows_verification_spools_to_a_throwaway_directory():
    commands = _powershell_commands()
    first_hook = next(i for i, c in enumerate(commands) if WINDOWS_MANAGED in c)
    assert any(c.startswith("$spool =") for c in commands[:first_hook])


def test_the_windows_t1_check_holds_no_literal_token():
    [t1] = [c for c in _powershell_commands() if "glpat-" in c]
    assert WINDOWS_MANAGED in t1
    assert not re.search(r"glpat-[A-Za-z0-9]", MDM)


def test_mdm_names_the_windows_paths_and_fragment():
    section = _section(MDM, "## What has to land on the machine")
    assert r"C:\Program Files\forgd\venv" in section
    assert r"C:\ProgramData\forgd\policy.yaml" in section
    assert "managed-settings.windows.fragment.json" in MDM


def test_the_intune_windows_detection_rule_is_the_venv_interpreter():
    intune = _section(MDM, "## Intune")
    assert "forgd-verdict.exe" not in intune
    assert r"C:\Program Files\forgd\venv\Scripts\python.exe" in intune


# --- Rollout order against the shipped files ----------------------------------------

POLICY = yaml.safe_load((ROOT / "policy.yaml").read_text())
FRAGMENT_FILES = ["managed-settings.fragment.json", "managed-settings.windows.fragment.json"]
ROLLOUT = _section(MDM, "## Rollout order")


@pytest.mark.parametrize("name", FRAGMENT_FILES)
def test_the_fragments_ship_locked(name):
    assert json.loads((ROOT / "deploy" / name).read_text())["allowManagedHooksOnly"] is True


def test_the_policy_ships_gitleaks_at_block():
    assert POLICY["detectors"]["gitleaks"]["severity"] == "block"
    assert POLICY["detectors"]["t0_regex"]["severity"] == "block"


def test_the_rollout_says_the_shipped_files_are_the_end_state():
    text = _flat(ROLLOUT)
    assert re.search(r"shipped .*(are|is) the end state of step 3", text), text
    assert '"allowManagedHooksOnly": false' in ROLLOUT
    assert "switch the hook off" in text and "time-boxed" in text


def _rollout_yaml() -> list[dict]:
    return [yaml.safe_load(b) for b in re.findall(r"```yaml\n(.*?)```", ROLLOUT, re.S)]


def test_the_rollout_relaxes_gitleaks_to_warn_then_restores_block():
    gitleaks = [b["detectors"]["gitleaks"] for b in _rollout_yaml()
                if "gitleaks" in (b.get("detectors") or {})]
    assert {"enabled": False} in gitleaks
    assert {"enabled": "auto", "severity": "warn"} in gitleaks
    shipped = POLICY["detectors"]["gitleaks"]
    assert {"enabled": shipped["enabled"], "severity": shipped["severity"]} in gitleaks


def test_every_detector_the_rollout_names_exists_in_the_policy():
    named = {k for b in _rollout_yaml() for k in (b.get("detectors") or {})}
    named |= set(re.findall(r"`detectors\.(\w+)", ROLLOUT))
    named |= {n for n in re.findall(r"`(\w+)`", ROLLOUT) if n in POLICY["detectors"]
              or n.endswith(("_regex", "_pii", "_exfil"))}
    assert named
    assert sorted(named - set(POLICY["detectors"])) == []


# --- Who can write what the hook runs --------------------------------------------------

STEP_1 = _flat(LANDS[LANDS.index("1. "):LANDS.index("\n2. ")])


def test_step_1_requires_an_admin_owned_venv_and_base_interpreter():
    """The venv's interpreter runs the base interpreter that `pyvenv.cfg`
    `home =` names, and loads its standard library."""
    assert "`pyvenv.cfg`" in STEP_1 and "`home =`" in STEP_1
    assert re.search(r"user-installed Python", STEP_1)


def test_the_windows_data_directory_drops_inherited_user_write():
    windows = [c for c in _powershell_commands() if c.startswith("icacls")]
    acl = [c for c in windows if "/inheritance:r" in c and "device-salt" not in c
           and "$path" not in c]
    assert acl, windows
    [grant] = acl
    assert r"C:\ProgramData\forgd" in grant
    for sid, right in (("S-1-5-18", "F"), ("S-1-5-32-544", "F"), ("S-1-5-32-545", "RX")):
        assert re.search(rf"\*{sid}:\(OI\)\(CI\){right}\b", grant), sid


def test_mdm_has_an_admin_check_for_both_platforms():
    check = _section(MDM, "## Checking who can write it")
    assert "pyvenv.cfg" in check
    assert re.search(r"ls -ld .*\$home", check)
    assert "/opt/forgd/bin/gitleaks" in check and "/etc/forgd/policy.yaml" in check
    assert "icacls" in check and "BUILTIN\\Users" in check


def test_mdm_lists_the_residuals_the_hook_cannot_close():
    residuals = _flat(_section(MDM, "## What the hook cannot protect against"))
    for name in ("LD_PRELOAD", "DYLD_", "USERPROFILE"):
        assert name in residuals, name
    assert "hook-ship" in residuals


# --- How the two fragments differ --------------------------------------------------------

LOCATIONS = re.compile(r"^File locations?\b")


def _comparable(name: str) -> dict:
    """The fragment with its paths replaced, the Windows title suffix
    removed and the file-location paragraph of `_comment` dropped."""
    fragment = _load_fragment(name)
    python, policy = FRAGMENT_PATHS[name]
    lines, skipping = [], False
    for line in fragment["_comment"]:
        if LOCATIONS.match(line):
            skipping = True
        elif skipping and line == "":
            skipping = False
            continue
        if not skipping:
            lines.append(line.replace("as a managed hook, for Windows.", "as a managed hook."))
    fragment["_comment"] = lines
    fragment["permissions"]["deny"] = ["Read(POLICY_DIR)" if r == POLICY_DIR_RULES[name] else r
                                       for r in fragment["permissions"]["deny"]]
    for event in fragment["hooks"].values():
        for entry in event:
            for hook in entry["hooks"]:
                argv = [hook["command"], *hook["args"]]
                if name == "managed-settings.fragment.json":
                    assert argv[:2] == ["/usr/bin/env", "-i"], argv
                    argv = argv[2:]
                assert argv[0] == python, argv
                hook["command"] = "PYTHON"
                hook["args"] = ["POLICY" if a == policy else a for a in argv[1:]]
    return fragment


FRAGMENT_PATHS = {
    "managed-settings.fragment.json": ("/opt/forgd/venv/bin/python", "/etc/forgd/policy.yaml"),
    "managed-settings.windows.fragment.json": (
        r"C:\Program Files\forgd\venv\Scripts\python.exe", r"C:\ProgramData\forgd\policy.yaml"),
}


def _load_fragment(name: str) -> dict:
    return json.loads((ROOT / "deploy" / name).read_text())


def test_the_fragment_difference_sentence_matches_the_fragments():
    sentence = ("The two differ in the interpreter and policy paths, in the policy "
                "directory their `permissions.deny` names, in the managed "
                "settings location their `_comment` gives, and in the macOS and Linux "
                "fragment starting the interpreter through `/usr/bin/env -i`.")
    assert sentence in _flat(LANDS)
    posix, windows = (_comparable(n) for n in FRAGMENT_FILES)
    assert windows == posix


MAC_PYTHON = "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12"
UV = "/opt/forgd/bin/uv"
WINDOWS_UV = r"C:\Program Files\forgd\bin\uv.exe"
FORGD = re.compile(r"(?<![\w./\\-])forgd[-_]verdict(?:[-_]hook)?(?:[=<>~!\[@ ]|$)")


def _uv_commands() -> list[str]:
    return [c for c in _bash_commands() + _powershell_commands()
            if re.search(r"(^|[\s&\"'])(\$uv|uv|\S*/uv|\S*\\uv\.exe)['\"]?\s+(pip|venv)\b", c)]


def _installs() -> list[str]:
    return [c for c in _uv_commands() if re.search(r"\bpip install\b", c)]


def test_mdm_installs_on_both_platforms():
    installs = _installs()
    assert len(installs) == 2, installs


def test_every_install_requires_hashes_and_builds_and_caches_nothing():
    for c in _installs():
        for flag in ("--require-hashes", "--no-build", "--link-mode=copy", "--no-cache",
                     "-r hook.txt", "-r forgd.txt"):
            assert flag in c, (flag, c)
        assert "--no-deps" not in c, c


def test_no_install_names_a_forgd_package_from_an_index():
    for c in _installs():
        assert not FORGD.search(c.split(" pip install ", 1)[1]), c


def test_uv_runs_from_an_admin_path():
    bash = "\n".join(re.findall(r"```bash\n(.*?)```", MDM, re.S))
    powershell = "\n".join(re.findall(r"```powershell\n(.*?)```", MDM, re.S))
    assert re.search(rf"^\s*uv={re.escape(UV)}$", bash, re.M)
    assert re.search(rf"^\s*\$uv = '{re.escape(WINDOWS_UV)}'$", powershell, re.M)
    for c in _uv_commands():
        assert c.startswith(('"$uv" ', "& $uv ")), c


def test_the_venv_is_built_on_an_admin_installed_interpreter():
    venvs = [c for c in _uv_commands() if " venv " in f" {c} "]
    assert len(venvs) == 3, venvs
    for c in venvs:
        assert "--no-python-downloads" in c, c
    pythons = {re.search(r"--python ('[^']+'|\S+)", c).group(1) for c in venvs}
    assert pythons == {MAC_PYTHON, "/usr/bin/python3.12",
                       r"'C:\Program Files\Python312\python.exe'"}
    assert "/usr/bin/python3.12" not in _flat(STEP_1).split("Linux")[0]
    assert "/opt/homebrew" in STEP_1 and "Homebrew" in STEP_1


def test_the_wheel_requirements_pin_each_release_wheel_by_hash(tmp_path):
    """Runs MDM.md's own line that turns SHA256SUMS into forgd.txt."""
    import subprocess

    [line] = [c for c in _bash_commands() if c.endswith("> forgd.txt")]
    sums = ("a" * 64 + "  forgd_verdict-1.2.3-py3-none-any.whl\n"
            + "b" * 64 + "  forgd_verdict_hook-1.2.3-py3-none-any.whl\n"
            + "c" * 64 + "  hook.txt\n")
    (tmp_path / "SHA256SUMS").write_text(sums)
    subprocess.run(["bash", "-c", line], cwd=tmp_path, check=True)
    assert (tmp_path / "forgd.txt").read_text() == (
        "forgd_verdict @ ./forgd_verdict-1.2.3-py3-none-any.whl --hash=sha256:" + "a" * 64 + "\n"
        "forgd_verdict_hook @ ./forgd_verdict_hook-1.2.3-py3-none-any.whl --hash=sha256:"
        + "b" * 64 + "\n")


def test_the_release_files_are_checked_before_the_install():
    bash = _bash_commands()
    check = next(i for i, c in enumerate(bash) if c.startswith("shasum -a 256 -c SHA256SUMS"))
    install = next(i for i, c in enumerate(bash) if " pip install " in c)
    assert check < install
    powershell = "\n".join(re.findall(r"```powershell\n(.*?)```", MDM, re.S))
    assert powershell.index("Get-FileHash") < powershell.index(" pip install ")
    assert "gh attestation verify" in STEP_1


def test_the_write_check_covers_uv_and_lets_gid_0_write():
    check = _section(MDM, "## Checking who can write it")
    [ls] = [c for c in _bash_commands() if c.startswith("ls -ld /opt/forgd ")]
    assert UV in ls.split()
    [find] = [c for c in _bash_commands() if c.startswith("find ")]
    assert UV in find.split() or "/opt/forgd/bin" in find.split()
    assert r"\( -perm -g=w ! -group 0 \)" in find
    assert r"icacls 'C:\Program Files\forgd' /T" in check


def _powershell_block(*needles: str) -> str:
    [block] = [b for b in re.findall(r"```powershell\n(.*?)```", MDM, re.S)
               if all(n in b for n in needles)]
    return block


def test_the_windows_data_directory_is_recreated_unless_admin_owned_and_link_free():
    block = _powershell_block(r"C:\ProgramData\forgd", "/setowner")
    setowner = block.index('/setowner "*S-1-5-32-544" /T')
    grant = block.index("/inheritance:r /grant:r")
    for check in ("[IO.FileAttributes]::ReparsePoint", "GetOwner(", "-Attributes ReparsePoint",
                  "$item.Delete()", "rmdir /s /q"):
        assert block.index(check) < setowner, check
    assert setowner < grant
    assert re.search(r"/inheritance:r /grant:r .*\(OI\)\(CI\)RX\" /T$", block, re.M)
    after = block[grant:]
    assert "GetOwner(" in after and "throw" in after
    assert "Remove-Item" not in block


def test_the_windows_write_check_lists_wrong_owners_and_links():
    check = _section(MDM, "## Checking who can write it")
    block = _powershell_block("Get-Content 'C:\\Program Files\\forgd\\venv\\pyvenv.cfg'")
    assert "GetOwner(" in block and "ReparsePoint" in block
    for path in (r"'C:\Program Files\forgd'", r"'C:\ProgramData\forgd'"):
        assert re.search(rf"foreach \(\$p in .*{re.escape(path)}", block), path
    assert "S-1-5-32-544" in block and "S-1-5-18" in block
    assert "owner" in _flat(check).lower()


GITLEAKS_ASSETS = ("darwin_arm64.tar.gz", "darwin_x64.tar.gz", "linux_x64.tar.gz",
                   "linux_arm64.tar.gz", "windows_x64.zip")


def _gitleaks_table() -> dict[str, str]:
    step4 = LANDS[LANDS.index("\n4. "):]
    return dict(re.findall(r"^\s*\| `(gitleaks_[^`]+)` \| `([^`]*)` \|$", step4, re.M))


def _dockerfile_gitleaks() -> str:
    dockerfile = (ROOT / "deploy" / "Dockerfile").read_text()
    [version] = set(re.findall(r"^ARG GITLEAKS_VERSION=(\S+)$", dockerfile, re.M))
    return version


def test_step_4_pins_the_image_gitleaks_for_every_laptop():
    version = _dockerfile_gitleaks()
    table = _gitleaks_table()
    assert set(table) == {f"gitleaks_{version}_{a}" for a in GITLEAKS_ASSETS}
    for asset, digest in table.items():
        assert re.fullmatch(r"[0-9a-f]{64}", digest), asset
    step4 = LANDS[LANDS.index("\n4. "):]
    urls = re.findall(r"github\.com/gitleaks/gitleaks/releases/download/(v[^/]+)/", step4)
    assert urls and set(urls) == {f"v{version}"}


def test_step_4_linux_hash_is_the_one_ci_installs():
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    assert ci["env"]["GITLEAKS_VERSION"] == _dockerfile_gitleaks()
    table = _gitleaks_table()
    assert table[f"gitleaks_{_dockerfile_gitleaks()}_linux_x64.tar.gz"] == ci["env"]["GITLEAKS_SHA256"]


def test_step_4_checks_the_archive_before_installing_it():
    table = _gitleaks_table()
    bash = "\n".join(_bash_commands())
    [(asset, digest)] = re.findall(r"^asset=(\S+)\nsha256=(\S+)$", bash, re.M)
    assert table[asset] == digest
    assert bash.index('shasum -a 256 -c') < bash.index("/opt/forgd/bin/gitleaks")
    assert "install -o 0 -g 0 -m 0755 gitleaks /opt/forgd/bin/gitleaks" in bash
    block = _powershell_block("Expand-Archive")
    [(win_asset, win_digest)] = re.findall(r"^\s*\$asset = '(\S+)'\n\s*\$sha256 = '(\S+)'$", block, re.M)
    assert table[win_asset] == win_digest
    assert block.index("Get-FileHash") < block.index("Expand-Archive")
    assert r"'C:\Program Files\forgd\bin\gitleaks.exe'" in block


@pytest.mark.parametrize("needle", ["shasum -a 256 -c SHA256SUMS", 'shasum -a 256 -c\n'])
def test_a_failed_checksum_stops_the_bash_block(needle):
    [block] = [b for b in re.findall(r"```bash\n(.*?)```", MDM, re.S) if needle in b]
    assert block.lstrip().startswith("set -eu\n"), block


SALT_RULE = "Read(~/.local/state/forgd-verdict/device-salt)"
POLICY_DIR_RULES = {"managed-settings.fragment.json": "Read(//etc/forgd/**)",
                    "managed-settings.windows.fragment.json": "Read(//c/ProgramData/forgd/**)"}


@pytest.mark.parametrize("name", POLICY_DIR_RULES)
def test_each_fragment_denies_reads_of_its_policy_directory_and_the_device_salt(name):
    fragment = _load_fragment(name)
    policy = _scan_hook_argv(name)[-1]
    posix = re.sub(r"^([A-Za-z]):", lambda m: "/" + m.group(1).lower(), policy.replace("\\", "/"))
    assert POLICY_DIR_RULES[name] == f"Read(/{posix.rsplit('/', 1)[0]}/**)"
    assert fragment["permissions"]["deny"] == [POLICY_DIR_RULES[name], SALT_RULE]


def test_mdm_recommends_the_shipped_deny_rules():
    section = _flat(_section(MDM, "## Keeping sensitive files out of Claude's reads"))
    for rule in (*POLICY_DIR_RULES.values(), SALT_RULE):
        assert f'"{rule}"' in section or f"`{rule}`" in section, rule
    assert "//C:" not in MDM
    assert "`/c/ProgramData/forgd`" in section
    assert "hook.spool" in section and "ca_file" in section


def test_the_provisioned_device_salt_is_read_only_to_users():
    section = _section(MDM, "### Provisioning the device salt")
    assert "device_salt_path: /etc/forgd/device-salt" in section
    assert "chmod 0444 /etc/forgd/device-salt" in section and "chown root" in section
    [grant] = [c for c in _powershell_commands() if c.startswith("icacls $path")]
    assert "/inheritance:r" in grant
    for sid, right in (("S-1-5-18", "F"), ("S-1-5-32-544", "F"), ("S-1-5-32-545", "R")):
        assert re.search(rf"\*{sid}:{right}\b", grant), sid
    assert not re.search(r"\*S-1-5-32-545:\S*[WMF]", grant)


def test_the_inventory_snippets_read_the_id_with_the_managed_policy():
    section = _section(MDM, "### Reporting the id to inventory")
    assert "--policy /etc/forgd/policy.yaml hook device-id" in section
    assert r"--policy C:\ProgramData\forgd\policy.yaml hook device-id" in section
