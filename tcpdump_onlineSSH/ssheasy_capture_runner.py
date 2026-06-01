#!/usr/bin/env python3
"""Automate tcpdump capture around a WebSSH browser session."""

import argparse
import base64
import ipaddress
import json
import logging
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode, urljoin
from urllib.request import urlopen

try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright
except ImportError as exc:  # pragma: no cover - import guard
    raise SystemExit(
        "Missing dependency 'playwright'. Install it with: pip install playwright"
    ) from exc


LOG = logging.getLogger("ssheasy-capture")

CONNECT_URL_STYLE_ALIASES = {
    "connect_params": "connect_params",
    "ssheasy": "connect_params",
    "webssh_query": "webssh_query",
    "webssh": "webssh_query",
    "webhorizon": "webssh_query",
}


class ConfigError(RuntimeError):
    """Raised when the JSON config is incomplete or invalid."""


@dataclass(frozen=True)
class SSHTransport:
    """Resolved SSH transport details for subprocess-based OpenSSH calls."""

    host: str
    port: int
    username: str
    password: Optional[str]
    private_key_path: Optional[Path]
    private_key_passphrase: Optional[str]
    connect_timeout_seconds: int
    look_for_keys: bool
    allow_agent: bool

    @property
    def remote(self) -> str:
        return f"{self.username}@{self.host}"

    @property
    def uses_password_auth(self) -> bool:
        return bool(self.password and not self.private_key_path)

    @property
    def uses_sshpass(self) -> bool:
        return bool(
            self.uses_password_auth
            or (self.private_key_path and self.private_key_passphrase)
        )

    def sshpass_prefix(self) -> list[str]:
        if self.private_key_path and self.private_key_passphrase:
            return ["sshpass", "-P", "Enter passphrase", "-p", self.private_key_passphrase]
        if self.uses_password_auth:
            return ["sshpass", "-p", self.password or ""]
        return []

    def shared_ssh_options(self) -> list[str]:
        options = [
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            f"ConnectTimeout={self.connect_timeout_seconds}",
        ]

        if not self.allow_agent:
            options.extend(["-o", "IdentityAgent=none"])

        if self.private_key_path:
            options.extend(["-i", str(self.private_key_path)])
            options.extend(["-o", "PreferredAuthentications=publickey"])
            if not self.look_for_keys:
                options.extend(["-o", "IdentitiesOnly=yes"])
        elif self.uses_password_auth:
            options.extend(["-o", "PreferredAuthentications=password,keyboard-interactive"])
            options.extend(["-o", "PubkeyAuthentication=no"])
            options.extend(["-o", "NumberOfPasswordPrompts=1"])
        elif not self.look_for_keys:
            options.extend(["-o", "PubkeyAuthentication=no"])

        if not self.uses_sshpass:
            options.extend(["-o", "BatchMode=yes"])

        return options

    def build_ssh_command(self, remote_command: str, *, get_pty: bool = False) -> list[str]:
        command = [*self.sshpass_prefix(), "ssh", *self.shared_ssh_options(), "-p", str(self.port)]
        if get_pty:
            command.append("-tt")
        command.extend([self.remote, remote_command])
        return command

    def build_scp_command(self, remote_path: str, local_path: Path) -> list[str]:
        remote_spec = f"{self.remote}:{shell_quote(remote_path)}"
        return [
            *self.sshpass_prefix(),
            "scp",
            *self.shared_ssh_options(),
            "-P",
            str(self.port),
            remote_spec,
            str(local_path),
        ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run repeated tcpdump captures around a WebSSH session."
    )
    parser.add_argument(
        "--config",
        default="tcpdump_onlineSSH/capture_config.local.json",
        help="Path to the JSON config file.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=None,
        help="Override the iteration count from the config.",
    )
    parser.add_argument(
        "--headful",
        action="store_true",
        help="Run the browser visibly instead of using headless mode.",
    )
    return parser.parse_args()


def load_config(config_path: Path) -> Dict[str, Any]:
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in {config_path}: {exc}") from exc


def require(config: Dict[str, Any], key: str, parent: str) -> Any:
    value = config.get(key)
    if value in (None, ""):
        raise ConfigError(f"Missing required config value: {parent}.{key}")
    return value


def resolve_local_path(config_dir: Path, value: Optional[str]) -> Optional[Path]:
    if not value:
        return None
    candidate = Path(os.path.expanduser(value))
    if not candidate.is_absolute():
        candidate = (config_dir / candidate).resolve()
    return candidate


def shell_quote(value: str) -> str:
    return shlex.quote(value)


def get_connect_url_style(online_ssh: Dict[str, Any]) -> str:
    configured_style = str(online_ssh.get("url_style", "connect_params")).strip().lower()
    style = CONNECT_URL_STYLE_ALIASES.get(configured_style)
    if style is None:
        supported = ", ".join(sorted(CONNECT_URL_STYLE_ALIASES))
        raise ConfigError(
            f"Unsupported online_ssh.url_style: {configured_style}. "
            f"Use one of: {supported}."
        )
    return style


def get_default_connect_path(url_style: str) -> str:
    if url_style == "webssh_query":
        return "/"
    return "/connect"


def build_connect_target(config: Dict[str, Any]) -> Dict[str, Any]:
    vm = config["vm"]
    online_ssh = config["online_ssh"]
    target = dict(online_ssh.get("target") or {})

    if "host" not in target:
        target["host"] = vm.get("host")
    if "port" not in target:
        target["port"] = vm.get("port", 22)
    if "user" not in target:
        target["user"] = vm.get("username")
    if "password" not in target:
        target["password"] = vm.get("password")

    require(target, "host", "online_ssh.target")
    require(target, "user", "online_ssh.target")
    require(target, "password", "online_ssh.target")
    target["port"] = int(target.get("port", 22))
    return target


def validate_config(config: Dict[str, Any], config_dir: Path) -> None:
    vm = config.get("vm") or {}
    capture = config.get("capture") or {}
    timing = config.get("timing") or {}
    online_ssh = config.get("online_ssh") or {}
    local = config.get("local") or {}

    if not vm:
        raise ConfigError("Missing 'vm' section in config.")
    if not capture:
        raise ConfigError("Missing 'capture' section in config.")
    if not online_ssh:
        raise ConfigError("Missing 'online_ssh' section in config.")
    if not local:
        raise ConfigError("Missing 'local' section in config.")

    require(vm, "host", "vm")
    require(vm, "username", "vm")
    require(vm, "remote_capture_dir", "vm")
    require(capture, "interface", "capture")
    require(local, "download_dir", "local")

    if not vm.get("password") and not vm.get("private_key_path"):
        raise ConfigError(
            "Set either vm.password or vm.private_key_path for the direct SSH login."
        )
    if vm.get("private_key_passphrase") and not vm.get("private_key_path"):
        raise ConfigError(
            "vm.private_key_passphrase requires vm.private_key_path to be set."
        )

    if online_ssh.get("connect_url"):
        require(online_ssh, "connect_url", "online_ssh")
    else:
        require(online_ssh, "base_url", "online_ssh")
        get_connect_url_style(online_ssh)

    build_connect_target(config)

    iterations = int(config.get("iterations", 10))
    if iterations < 1:
        raise ConfigError("iterations must be at least 1.")

    start_iteration = int(config.get("start_iteration", 1))
    if start_iteration < 1:
        raise ConfigError("start_iteration must be at least 1.")
    if start_iteration > iterations:
        raise ConfigError("start_iteration cannot be greater than iterations.")

    wait_seconds = int(timing.get("online_session_seconds", 120))
    if wait_seconds < 1:
        raise ConfigError("timing.online_session_seconds must be at least 1.")

    reconnect_delay = int(timing.get("reconnect_delay_seconds", 10))
    if reconnect_delay < 0:
        raise ConfigError("timing.reconnect_delay_seconds cannot be negative.")

    private_key_path = resolve_local_path(config_dir, vm.get("private_key_path"))
    if private_key_path and not private_key_path.exists():
        raise ConfigError(f"Private key not found: {private_key_path}")

    browser_executable = resolve_local_path(
        config_dir, online_ssh.get("browser_executable")
    )
    if browser_executable and not browser_executable.exists():
        raise ConfigError(f"Browser executable not found: {browser_executable}")

    public_ip_log_file = resolve_local_path(config_dir, local.get("public_ip_log_file"))
    if public_ip_log_file is not None and public_ip_log_file.is_dir():
        raise ConfigError("local.public_ip_log_file must be a file path, not a directory.")

    public_ip_lookup_urls = local.get("public_ip_lookup_urls")
    if public_ip_lookup_urls is not None and not isinstance(public_ip_lookup_urls, list):
        raise ConfigError("local.public_ip_lookup_urls must be a list of URLs.")


def build_ssh_transport(config: Dict[str, Any], config_dir: Path) -> SSHTransport:
    vm = config["vm"]
    return SSHTransport(
        host=str(vm["host"]),
        port=int(vm.get("port", 22)),
        username=str(vm["username"]),
        password=vm.get("password"),
        private_key_path=resolve_local_path(config_dir, vm.get("private_key_path")),
        private_key_passphrase=vm.get("private_key_passphrase"),
        connect_timeout_seconds=int(vm.get("connect_timeout_seconds", 20)),
        look_for_keys=bool(vm.get("look_for_keys", False)),
        allow_agent=bool(vm.get("allow_agent", False)),
    )


def ensure_local_ssh_dependencies(ssh_transport: SSHTransport) -> None:
    for binary in ("ssh", "scp"):
        if shutil.which(binary) is None:
            raise RuntimeError(
                f"Missing local dependency '{binary}'. Install OpenSSH client tools."
            )

    if ssh_transport.uses_sshpass and shutil.which("sshpass") is None:
        raise RuntimeError(
            "Missing local dependency 'sshpass'. Install sshpass for password-based "
            "direct SSH control, or switch vm.private_key_path to key-based auth."
        )


def run_local_command(
    command: list[str],
    *,
    description: str,
    check: bool = True,
    timeout: Optional[int] = None,
) -> Tuple[str, str, int]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        raise RuntimeError(
            f"{description} timed out after {timeout} seconds.\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}"
        ) from exc

    stdout = completed.stdout
    stderr = completed.stderr
    if check and completed.returncode != 0:
        extra_hint = ""
        if completed.returncode == 255 and command:
            command_name = Path(command[0]).name
            if command_name in {"ssh", "scp", "sshpass"}:
                extra_hint = (
                    "\nHint: exit 255 from OpenSSH usually means the SSH connection "
                    "or authentication failed before the remote command ran."
                )
        raise RuntimeError(
            f"{description} failed (exit {completed.returncode}).\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}"
            f"{extra_hint}"
        )
    return stdout, stderr, completed.returncode


def exec_remote(
    ssh_transport: SSHTransport,
    command: str,
    *,
    check: bool = True,
    get_pty: bool = False,
    timeout: Optional[int] = None,
    description: Optional[str] = None,
) -> Tuple[str, str, int]:
    return run_local_command(
        ssh_transport.build_ssh_command(command, get_pty=get_pty),
        description=description or f"Remote command failed: {command}",
        check=check,
        timeout=timeout,
    )


def tmux_send_literal(
    ssh_transport: SSHTransport,
    session_name: str,
    text: str,
    *,
    press_enter: bool = True,
    sensitive: bool = False,
) -> None:
    exec_remote(
        ssh_transport,
        "tmux send-keys -t {session} -l {text}".format(
            session=shell_quote(session_name),
            text=shell_quote(text),
        ),
        description=(
            "Remote command failed: tmux send-keys <redacted>"
            if sensitive
            else None
        ),
    )
    if press_enter:
        exec_remote(
            ssh_transport,
            "tmux send-keys -t {session} Enter".format(
                session=shell_quote(session_name)
            ),
        )


def capture_tmux_pane(ssh_transport: SSHTransport, session_name: str) -> str:
    output, _, _ = exec_remote(
        ssh_transport,
        "tmux capture-pane -p -t {session} -S -50".format(
            session=shell_quote(session_name)
        ),
        check=False,
    )
    return output


def tmux_session_exists(ssh_transport: SSHTransport, session_name: str) -> bool:
    _, _, exit_code = exec_remote(
        ssh_transport,
        "tmux has-session -t {session}".format(session=shell_quote(session_name)),
        check=False,
    )
    return exit_code == 0


def build_tcpdump_command(
    config: Dict[str, Any],
    remote_pcap_path: str,
) -> str:
    capture = config["capture"]
    vm = config["vm"]
    command_parts = []

    if bool(capture.get("require_sudo", True)):
        command_parts.extend(["sudo", "-S"])

    command_parts.extend(
        [
            "tcpdump",
            "-U",
            "-i",
            str(capture["interface"]),
            "-w",
            remote_pcap_path,
        ]
    )

    extra_args = capture.get("extra_args") or []
    if not isinstance(extra_args, list):
        raise ConfigError("capture.extra_args must be a list of strings.")
    command_parts.extend(str(arg) for arg in extra_args)

    bpf_filter = capture.get("bpf_filter")
    if bpf_filter:
        command_parts.append(str(bpf_filter))

    if bool(capture.get("require_sudo", True)) and not vm.get("sudo_password"):
        LOG.warning(
            "capture.require_sudo is true but vm.sudo_password is empty. "
            "This only works if the remote user can run sudo without a password."
        )

    return shlex.join(command_parts)


def render_remote_name(template: str, iteration: int, timestamp: str) -> str:
    try:
        return template.format(iteration=iteration, timestamp=timestamp)
    except KeyError as exc:
        raise ConfigError(
            f"Unsupported template placeholder in '{template}': {exc}"
        ) from exc


def build_remote_pcap_path(
    config: Dict[str, Any],
    iteration: int,
    timestamp: str,
) -> str:
    vm = config["vm"]
    capture = config["capture"]
    remote_capture_dir = str(vm["remote_capture_dir"])
    remote_template = str(
        capture.get("remote_pcap_template", "capture_{iteration:02d}_{timestamp}.pcap")
    )
    rendered = render_remote_name(remote_template, iteration, timestamp)
    if rendered.startswith("/"):
        return rendered
    return posixpath.join(remote_capture_dir, rendered)


def build_tmux_session_name(
    config: Dict[str, Any],
    iteration: int,
    timestamp: str,
) -> str:
    vm = config["vm"]
    template = str(
        vm.get("tmux_session_template", "online_ssh_capture_{iteration:02d}_{timestamp}")
    )
    return render_remote_name(template, iteration, timestamp)


def start_tcpdump(
    ssh_transport: SSHTransport,
    config: Dict[str, Any],
    *,
    iteration: int,
    timestamp: str,
) -> Tuple[str, str]:
    session_name = build_tmux_session_name(config, iteration, timestamp)
    remote_pcap_path = build_remote_pcap_path(config, iteration, timestamp)
    remote_dir = posixpath.dirname(remote_pcap_path)
    startup_timeout = int(
        config.get("timing", {}).get("tcpdump_startup_timeout_seconds", 20)
    )

    exec_remote(
        ssh_transport, "mkdir -p {path}".format(path=shell_quote(remote_dir))
    )
    exec_remote(
        ssh_transport,
        "tmux new-session -d -s {session}".format(session=shell_quote(session_name)),
    )
    time.sleep(1)

    tcpdump_command = build_tcpdump_command(config, remote_pcap_path)
    tmux_send_literal(ssh_transport, session_name, tcpdump_command)

    sudo_password = config["vm"].get("sudo_password")
    require_sudo = bool(config["capture"].get("require_sudo", True))
    sent_sudo_password = False

    deadline = time.time() + startup_timeout
    while time.time() < deadline:
        pane_output = capture_tmux_pane(ssh_transport, session_name).lower()
        if "listening on" in pane_output:
            LOG.info("tcpdump is running in tmux session %s", session_name)
            return session_name, remote_pcap_path
        if (
            require_sudo
            and sudo_password
            and not sent_sudo_password
            and any(marker in pane_output for marker in ("password", "[sudo]"))
        ):
            tmux_send_literal(
                ssh_transport,
                session_name,
                str(sudo_password),
                sensitive=True,
            )
            sent_sudo_password = True
            time.sleep(1)
            continue
        if any(
            marker in pane_output
            for marker in (
                "sorry, try again",
                "command not found",
                "permission denied",
                "no such file or directory",
                "syntax error",
            )
        ):
            raise RuntimeError(
                "tcpdump failed to start in tmux session "
                f"{session_name}. tmux output:\n{pane_output}"
            )
        if not tmux_session_exists(ssh_transport, session_name):
            raise RuntimeError(f"tmux session {session_name} exited unexpectedly.")
        time.sleep(1)

    raise RuntimeError(
        "Timed out waiting for tcpdump to start. Last tmux output:\n"
        f"{capture_tmux_pane(ssh_transport, session_name)}"
    )

def find_matching_tcpdump_processes(
    ssh_transport: SSHTransport,
    remote_pcap_path: str,
) -> list[str]:
    output, _, _ = exec_remote(
        ssh_transport,
        "pgrep -af tcpdump",
        check=False,
    )
    matches = []
    for line in output.splitlines():
        cleaned = line.strip()
        if cleaned and remote_pcap_path in cleaned:
            matches.append(cleaned)
    return matches


def signal_matching_tcpdump_processes(
    ssh_transport: SSHTransport,
    remote_pcap_path: str,
    signal_name: str,
) -> None:
    regex_pattern = re.escape(remote_pcap_path)
    exec_remote(
        ssh_transport,
        "pkill -{signal_name} -f {pattern}".format(
            signal_name=signal_name,
            pattern=shell_quote(regex_pattern),
        ),
        check=False,
    )


def get_remote_file_size(ssh_transport: SSHTransport, remote_path: str) -> int:
    output, _, _ = exec_remote(
        ssh_transport,
        "stat -c %s {path}".format(path=shell_quote(remote_path)),
    )
    return int(output.strip())


def wait_for_remote_pcap_to_settle(
    ssh_transport: SSHTransport,
    remote_pcap_path: str,
    config: Dict[str, Any],
) -> int:
    settle_timeout = int(
        config.get("timing", {}).get("pcap_settle_timeout_seconds", 20)
    )
    poll_interval = int(
        config.get("timing", {}).get("pcap_settle_poll_seconds", 2)
    )
    last_size = None
    stable_reads = 0
    deadline = time.time() + settle_timeout

    while time.time() < deadline:
        matching_processes = find_matching_tcpdump_processes(ssh_transport, remote_pcap_path)
        current_size = get_remote_file_size(ssh_transport, remote_pcap_path)

        if current_size == last_size:
            stable_reads += 1
        else:
            stable_reads = 0
            last_size = current_size

        if not matching_processes and stable_reads >= 1:
            LOG.info("Remote pcap is stable at %s bytes", current_size)
            return current_size

        time.sleep(poll_interval)

    remaining_processes = find_matching_tcpdump_processes(ssh_transport, remote_pcap_path)
    raise RuntimeError(
        "Remote pcap did not settle before download. "
        f"active_tcpdump_processes={remaining_processes} "
        f"last_size={last_size}"
    )


def build_remote_snapshot_path(remote_pcap_path: str) -> str:
    return f"{remote_pcap_path}.download"


def create_remote_download_snapshot(
    ssh_transport: SSHTransport,
    remote_pcap_path: str,
) -> str:
    snapshot_path = build_remote_snapshot_path(remote_pcap_path)
    exec_remote(
        ssh_transport,
        "cp -f {source} {target}".format(
            source=shell_quote(remote_pcap_path),
            target=shell_quote(snapshot_path),
        ),
    )
    return snapshot_path


def stop_tcpdump(
    ssh_transport: SSHTransport,
    session_name: str,
    remote_pcap_path: str,
    config: Dict[str, Any],
) -> None:
    shutdown_timeout = int(
        config.get("timing", {}).get("tcpdump_shutdown_timeout_seconds", 15)
    )
    sent_int = False
    sent_term = False
    start_time = time.time()
    deadline = start_time + shutdown_timeout

    if tmux_session_exists(ssh_transport, session_name):
        exec_remote(
            ssh_transport,
            "tmux send-keys -t {session} C-c".format(session=shell_quote(session_name)),
            check=False,
        )
    else:
        LOG.warning("tmux session %s no longer exists while stopping tcpdump", session_name)

    while time.time() < deadline:
        matching_processes = find_matching_tcpdump_processes(ssh_transport, remote_pcap_path)
        if not matching_processes:
            exec_remote(
                ssh_transport,
                "tmux kill-session -t {session}".format(session=shell_quote(session_name)),
                check=False,
            )
            LOG.info("Stopped remote tcpdump for %s", remote_pcap_path)
            return

        elapsed = time.time() - start_time
        if elapsed >= 3 and not sent_int:
            signal_matching_tcpdump_processes(ssh_transport, remote_pcap_path, "INT")
            sent_int = True
        if elapsed >= 8 and not sent_term:
            signal_matching_tcpdump_processes(ssh_transport, remote_pcap_path, "TERM")
            sent_term = True
        time.sleep(1)

    signal_matching_tcpdump_processes(ssh_transport, remote_pcap_path, "KILL")
    time.sleep(1)
    remaining_processes = find_matching_tcpdump_processes(ssh_transport, remote_pcap_path)
    exec_remote(
        ssh_transport,
        "tmux kill-session -t {session}".format(session=shell_quote(session_name)),
        check=False,
    )
    if remaining_processes:
        pane_output = (
            capture_tmux_pane(ssh_transport, session_name)
            if tmux_session_exists(ssh_transport, session_name)
            else ""
        )
        raise RuntimeError(
            "Failed to stop remote tcpdump before download. "
            f"active_tcpdump_processes={remaining_processes} "
            f"tmux_output={pane_output}"
        )
    LOG.info("Stopped remote tcpdump for %s after forced termination", remote_pcap_path)


def remote_preflight(ssh_transport: SSHTransport) -> None:
    ensure_local_ssh_dependencies(ssh_transport)
    for binary in ("tmux", "tcpdump"):
        exec_remote(
            ssh_transport,
            "command -v {binary}".format(binary=shell_quote(binary)),
        )


def download_remote_pcap(
    ssh_transport: SSHTransport,
    remote_pcap_path: str,
    local_dir: Path,
    remove_remote: bool,
    *,
    local_filename: Optional[str] = None,
    always_remove_remote_paths: Optional[list[str]] = None,
    remove_remote_after_download_paths: Optional[list[str]] = None,
) -> Path:
    local_dir.mkdir(parents=True, exist_ok=True)
    local_path = local_dir / (local_filename or Path(remote_pcap_path).name)
    always_remove_remote_paths = always_remove_remote_paths or []
    remove_remote_after_download_paths = remove_remote_after_download_paths or []

    exec_remote(
        ssh_transport,
        "test -f {path}".format(path=shell_quote(remote_pcap_path)),
    )
    run_local_command(
        ssh_transport.build_scp_command(remote_pcap_path, local_path),
        description=f"Remote copy failed for {remote_pcap_path}",
    )

    for remote_path in always_remove_remote_paths:
        exec_remote(
            ssh_transport,
            "rm -f {path}".format(path=shell_quote(remote_path)),
            check=False,
        )
    if remove_remote:
        for remote_path in remove_remote_after_download_paths:
            exec_remote(
                ssh_transport,
                "rm -f {path}".format(path=shell_quote(remote_path)),
                check=False,
            )

    return local_path


def get_public_ip_log_path(config: Dict[str, Any], config_dir: Path) -> Path:
    local = config["local"]
    configured_path = resolve_local_path(config_dir, local.get("public_ip_log_file"))
    if configured_path is not None:
        return configured_path

    local_dir = resolve_local_path(config_dir, local.get("download_dir"))
    if local_dir is None:
        raise ConfigError("local.download_dir is required.")
    return local_dir / "public_ip_log.txt"


def fetch_public_ip(config: Dict[str, Any]) -> str:
    lookup_urls = config["local"].get("public_ip_lookup_urls") or [
        "https://api.ipify.org?format=json",
        "https://checkip.amazonaws.com",
        "https://ifconfig.me/ip",
    ]
    errors = []

    for lookup_url in lookup_urls:
        try:
            with urlopen(str(lookup_url), timeout=10) as response:
                body = response.read().decode("utf-8", errors="replace").strip()

            candidate = body
            if body.startswith("{"):
                payload = json.loads(body)
                candidate = str(payload["ip"]).strip()
            else:
                candidate = body.splitlines()[0].strip()

            ipaddress.ip_address(candidate)
            return candidate
        except Exception as exc:
            errors.append(f"{lookup_url}: {exc}")

    raise RuntimeError("; ".join(errors))


def record_public_ip(config: Dict[str, Any], config_dir: Path, iteration: int) -> None:
    log_path = get_public_ip_log_path(config, config_dir)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")

    try:
        public_ip = fetch_public_ip(config)
        line = f"{timestamp} iteration={iteration:03d} public_ip={public_ip}\n"
        LOG.info("Recorded public IP %s for iteration %s", public_ip, iteration)
    except Exception as exc:
        safe_error = str(exc).replace("\n", " ").strip()
        line = (
            f"{timestamp} iteration={iteration:03d} "
            f"public_ip_lookup_failed={safe_error}\n"
        )
        LOG.warning("Failed to record public IP for iteration %s: %s", iteration, safe_error)

    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(line)


def build_connect_url(config: Dict[str, Any]) -> str:
    online_ssh = config["online_ssh"]
    target = build_connect_target(config)

    if online_ssh.get("connect_url"):
        return str(online_ssh["connect_url"])

    url_style = get_connect_url_style(online_ssh)
    base_url = str(online_ssh["base_url"]).rstrip("/") + "/"
    connect_path = str(
        online_ssh.get("connect_path") or get_default_connect_path(url_style)
    ).lstrip("/")
    connect_url = urljoin(base_url, connect_path)

    if url_style == "webssh_query":
        password = base64.b64encode(
            str(target["password"]).encode("utf-8")
        ).decode("ascii")
        query = urlencode(
            {
                "hostname": target["host"],
                "port": target["port"],
                "username": target["user"],
                "password": password,
            }
        )
    else:
        query = urlencode(
            {
                "host": target["host"],
                "port": target["port"],
                "user": target["user"],
                "password": target["password"],
            }
        )
    return f"{connect_url}?{query}"


def maybe_click(page: Any, selector: Optional[str], timeout_ms: int) -> bool:
    if not selector:
        return False
    try:
        locator = page.locator(selector).first
        locator.wait_for(state="visible", timeout=timeout_ms)
        locator.click()
        return True
    except PlaywrightTimeoutError:
        return False


def maybe_click_button(page: Any, label: str, timeout_ms: int) -> bool:
    try:
        button = page.get_by_role("button", name=label, exact=True).first
        button.wait_for(state="visible", timeout=timeout_ms)
        button.click()
        return True
    except PlaywrightTimeoutError:
        return False


def wait_for_selector(page: Any, selector: Optional[str], timeout_ms: int) -> None:
    if not selector:
        return
    page.locator(selector).first.wait_for(state="visible", timeout=timeout_ms)


def launch_browser(
    playwright: Any,
    browser_name: str,
    browser_executable: Optional[Path],
    headless: bool,
) -> Any:
    browsers = {
        "chromium": playwright.chromium,
        "firefox": playwright.firefox,
        "webkit": playwright.webkit,
    }
    if browser_name not in browsers:
        raise ConfigError(
            f"Unsupported online_ssh.browser_name: {browser_name}. "
            "Use one of: chromium, firefox, webkit."
        )

    primary_browser = browsers[browser_name]
    fallback_order = [browser_name]
    if browser_name != "firefox":
        fallback_order.append("firefox")

    attempts = []
    if browser_executable:
        attempts.append(
            (
                f"{browser_name} at {browser_executable}",
                browser_name,
                primary_browser,
                {"executable_path": str(browser_executable)},
            )
        )
    for fallback_name in fallback_order:
        attempts.append(
            (
                f"Playwright bundled {fallback_name}",
                fallback_name,
                browsers[fallback_name],
                {},
            )
        )

    errors = []
    tried_attempts = set()
    for label, attempt_browser_name, browser_launcher, kwargs in attempts:
        fingerprint = (attempt_browser_name, kwargs.get("executable_path"))
        if fingerprint in tried_attempts:
            continue
        tried_attempts.add(fingerprint)
        try:
            LOG.info("Launching %s", label)
            return browser_launcher.launch(headless=headless, **kwargs)
        except Exception as exc:
            errors.append((label, exc))
            LOG.warning("Failed to launch %s: %s", label, exc)

    failure_lines = [
        f"{label}: {exc}"
        for label, exc in errors
    ]
    raise RuntimeError("Unable to launch browser.\n" + "\n".join(failure_lines))


def run_online_ssh_session(config: Dict[str, Any], config_dir: Path, headful: bool) -> None:
    online_ssh = config["online_ssh"]
    timing = config.get("timing", {})
    connect_url = build_connect_url(config)
    browser_executable = resolve_local_path(config_dir, online_ssh.get("browser_executable"))
    browser_name = str(online_ssh.get("browser_name", "firefox")).lower()
    timeout_ms = int(timing.get("browser_navigation_timeout_seconds", 30000))
    connected_wait_seconds = int(timing.get("online_session_seconds", 120))
    post_connect_delay = int(online_ssh.get("post_connect_delay_seconds", 0))
    browser_headless = not headful and bool(online_ssh.get("headless", True))

    connect_target = build_connect_target(config)
    LOG.info(
        "Opening WebSSH for %s@%s:%s",
        connect_target["user"],
        connect_target["host"],
        connect_target["port"],
    )
    LOG.info(
        "Launching %s in %s mode",
        browser_name,
        "headless" if browser_headless else "headful",
    )

    with sync_playwright() as playwright:
        browser = launch_browser(
            playwright,
            browser_name,
            browser_executable,
            browser_headless,
        )
        try:
            context = browser.new_context(
                ignore_https_errors=bool(online_ssh.get("ignore_https_errors", True))
            )
            page = context.new_page()
            page.goto(connect_url, wait_until="domcontentloaded", timeout=timeout_ms)

            wait_for_selector(page, online_ssh.get("page_ready_selector"), timeout_ms)

            # WebSSH can require an explicit Connect click and/or host-key acceptance.
            for _ in range(3):
                clicked_connect = maybe_click(
                    page, online_ssh.get("connect_button_selector"), 2000
                ) or maybe_click_button(page, "Connect", 2000)
                clicked_yes = maybe_click(
                    page, online_ssh.get("accept_host_key_selector"), 2000
                ) or maybe_click_button(page, "Yes", 2000)
                if not clicked_connect and not clicked_yes:
                    break
                time.sleep(1)

            if post_connect_delay > 0:
                time.sleep(post_connect_delay)

            LOG.info("Keeping the browser session open for %s seconds", connected_wait_seconds)
            time.sleep(connected_wait_seconds)

            clicked_disconnect = maybe_click(
                page,
                online_ssh.get("disconnect_button_selector"),
                5000,
            ) or maybe_click_button(page, "Disconnect", 2000)
            if clicked_disconnect:
                LOG.info("Clicked the configured disconnect selector before closing the page")

            context.close()
        finally:
            browser.close()


def best_effort_cleanup(
    config: Dict[str, Any],
    config_dir: Path,
    session_name: Optional[str],
    remote_pcap_path: Optional[str],
) -> None:
    if not session_name or not remote_pcap_path:
        return

    LOG.warning("Attempting to clean up tmux session %s", session_name)
    try:
        ssh_transport = build_ssh_transport(config, config_dir)
        if tmux_session_exists(ssh_transport, session_name):
            stop_tcpdump(ssh_transport, session_name, remote_pcap_path, config)
    except Exception as exc:  # pragma: no cover - cleanup only
        LOG.warning("Best-effort cleanup failed: %s", exc)


def run_iteration(
    config: Dict[str, Any],
    config_dir: Path,
    *,
    iteration: int,
    total_iterations: int,
    headful: bool,
) -> Path:
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    reconnect_delay = int(config.get("timing", {}).get("reconnect_delay_seconds", 10))
    local_dir = resolve_local_path(config_dir, config["local"]["download_dir"])
    if local_dir is None:
        raise ConfigError("local.download_dir is required.")

    LOG.info("Starting iteration %s/%s", iteration, total_iterations)
    record_public_ip(config, config_dir, iteration)

    ssh_transport = build_ssh_transport(config, config_dir)
    session_name = None
    remote_pcap_path = None
    remote_preflight(ssh_transport)
    session_name, remote_pcap_path = start_tcpdump(
        ssh_transport,
        config,
        iteration=iteration,
        timestamp=timestamp,
    )
    LOG.info(
        "Started remote capture at %s in tmux session %s",
        remote_pcap_path,
        session_name,
    )

    try:
        LOG.info("Disconnected from the VM and leaving tcpdump running in tmux")
        run_online_ssh_session(config, config_dir, headful=headful)

        if reconnect_delay:
            LOG.info("Waiting %s seconds before reconnecting to the VM", reconnect_delay)
            time.sleep(reconnect_delay)

        if session_name is None or remote_pcap_path is None:
            raise RuntimeError("tcpdump session state was not initialized.")
        stop_tcpdump(ssh_transport, session_name, remote_pcap_path, config)
        wait_for_remote_pcap_to_settle(ssh_transport, remote_pcap_path, config)
        remote_snapshot_path = create_remote_download_snapshot(
            ssh_transport,
            remote_pcap_path,
        )
        local_path = download_remote_pcap(
            ssh_transport,
            remote_snapshot_path,
            local_dir,
            bool(config["local"].get("remove_remote_after_download", False)),
            local_filename=Path(remote_pcap_path).name,
            always_remove_remote_paths=[remote_snapshot_path],
            remove_remote_after_download_paths=[remote_pcap_path],
        )
        LOG.info("Downloaded %s", local_path)
        return local_path
    except Exception:
        best_effort_cleanup(config, config_dir, session_name, remote_pcap_path)
        raise


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main() -> int:
    configure_logging()
    args = parse_args()
    config_path = Path(args.config).expanduser().resolve()
    config_dir = config_path.parent

    try:
        config = load_config(config_path)
        validate_config(config, config_dir)
    except ConfigError as exc:
        LOG.error("%s", exc)
        return 2

    iterations = args.iterations or int(config.get("iterations", 10))
    start_iteration = int(config.get("start_iteration", 1))
    if start_iteration > iterations:
        LOG.error("start_iteration cannot be greater than iterations.")
        return 2
    downloaded_files = []

    try:
        for iteration in range(start_iteration, iterations + 1):
            local_path = run_iteration(
                config,
                config_dir,
                iteration=iteration,
                total_iterations=iterations,
                headful=args.headful,
            )
            downloaded_files.append(local_path)
    except Exception as exc:  # pragma: no cover - runtime safety
        LOG.exception("Workflow failed: %s", exc)
        return 1

    LOG.info(
        "Completed iterations %s through %s (%s runs)",
        start_iteration,
        iterations,
        iterations - start_iteration + 1,
    )
    for local_path in downloaded_files:
        LOG.info("Saved pcap: %s", local_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
