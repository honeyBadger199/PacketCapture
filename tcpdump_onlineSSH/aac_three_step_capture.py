#!/usr/bin/env python3
"""Run the requested three tcpdump captures and save them into ./aac."""

import argparse
import copy
import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from ssheasy_capture_runner import (
    ConfigError,
    best_effort_cleanup,
    build_ssh_transport,
    configure_logging,
    create_remote_download_snapshot,
    download_remote_pcap,
    load_config,
    remote_preflight,
    record_public_ip,
    run_online_ssh_session,
    start_tcpdump,
    stop_tcpdump,
    validate_config,
    wait_for_remote_pcap_to_settle,
)


LOG = logging.getLogger("aac-three-step-capture")
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = str(SCRIPT_DIR / "capture_config.example.json")
DEFAULT_START_ITERATION = 14
DEFAULT_END_ITERATION = 50
REQUESTED_BPF_FILTER = "port 22 or port 443"


@dataclass(frozen=True)
class CaptureStep:
    label: str
    iteration: int
    use_ssheasy: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Start tcpdump on the VM in tmux, wait or connect through ssheasy.com, "
            "then stop tcpdump and SCP each pcap into the local aac folder."
        )
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG,
        help="JSON config containing VM and ssheasy.com credentials.",
    )
    parser.add_argument(
        "--output-dir",
        default="aac",
        help="Local folder where downloaded pcaps will be saved.",
    )
    parser.add_argument(
        "--duration-seconds",
        type=int,
        default=180,
        help="How long each capture should run. Default: 180 seconds.",
    )
    parser.add_argument(
        "--start-iteration",
        type=int,
        default=DEFAULT_START_ITERATION,
        help=f"First iteration number to run. Default: {DEFAULT_START_ITERATION}.",
    )
    parser.add_argument(
        "--end-iteration",
        type=int,
        default=DEFAULT_END_ITERATION,
        help=f"Last iteration number to run. Default: {DEFAULT_END_ITERATION}.",
    )
    parser.add_argument(
        "--headful",
        action="store_true",
        help="Show the ssheasy.com browser window during step 2.",
    )
    return parser.parse_args()


def resolve_output_dir(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()


def validate_iteration_range(start_iteration: int, end_iteration: int) -> None:
    if start_iteration < 1:
        raise ConfigError("--start-iteration must be at least 1.")
    if end_iteration < 1:
        raise ConfigError("--end-iteration must be at least 1.")
    if start_iteration > end_iteration:
        raise ConfigError("--start-iteration cannot be greater than --end-iteration.")


def apply_requested_overrides(
    config: Dict[str, Any],
    *,
    output_dir: Path,
    duration_seconds: int,
) -> Dict[str, Any]:
    if duration_seconds < 1:
        raise ConfigError("--duration-seconds must be at least 1.")

    updated = copy.deepcopy(config)
    updated.setdefault("timing", {})["online_session_seconds"] = duration_seconds
    updated.setdefault("capture", {})["interface"] = "any"
    updated["capture"]["bpf_filter"] = REQUESTED_BPF_FILTER

    extra_args = [str(arg) for arg in updated["capture"].get("extra_args") or []]
    if "-n" not in extra_args:
        extra_args.append("-n")
    updated["capture"]["extra_args"] = extra_args

    updated.setdefault("local", {})["download_dir"] = str(output_dir)
    updated["local"]["public_ip_log_file"] = str(output_dir / "public_ip_log.txt")
    return updated


def config_for_step(
    config: Dict[str, Any],
    step: CaptureStep,
    timestamp: str,
) -> Dict[str, Any]:
    remote_name = f"{step.label}_{timestamp}.pcap"

    step_config = copy.deepcopy(config)
    step_config["capture"]["remote_pcap_template"] = remote_name
    step_config["vm"]["tmux_session_template"] = f"{step.label}_{{timestamp}}"
    return step_config


def stop_settle_and_download(
    *,
    ssh_transport: Any,
    config: Dict[str, Any],
    session_name: str,
    remote_pcap_path: str,
    output_dir: Path,
) -> Path:
    stop_tcpdump(ssh_transport, session_name, remote_pcap_path, config)
    wait_for_remote_pcap_to_settle(ssh_transport, remote_pcap_path, config)
    remote_snapshot_path = create_remote_download_snapshot(ssh_transport, remote_pcap_path)
    return download_remote_pcap(
        ssh_transport,
        remote_snapshot_path,
        output_dir,
        bool(config["local"].get("remove_remote_after_download", False)),
        local_filename=Path(remote_pcap_path).name,
        always_remove_remote_paths=[remote_snapshot_path],
        remove_remote_after_download_paths=[remote_pcap_path],
    )


def run_capture_step(
    *,
    base_config: Dict[str, Any],
    config_dir: Path,
    step: CaptureStep,
    duration_seconds: int,
    headful: bool,
    output_dir: Path,
) -> Path:
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    config = config_for_step(base_config, step, timestamp)
    ssh_transport = build_ssh_transport(config, config_dir)
    session_name: Optional[str] = None
    remote_pcap_path: Optional[str] = None

    LOG.info("Starting %s", step.label)
    session_name, remote_pcap_path = start_tcpdump(
        ssh_transport,
        config,
        iteration=step.iteration,
        timestamp=timestamp,
    )
    LOG.info("tcpdump is running in tmux session %s", session_name)

    try:
        if step.use_ssheasy:
            LOG.info(
                "Opening ssheasy.com and keeping the session up for %s seconds",
                duration_seconds,
            )
            run_online_ssh_session(config, config_dir, headful=headful)
        else:
            LOG.info(
                "Disconnected from VM control SSH; waiting %s seconds",
                duration_seconds,
            )
            time.sleep(duration_seconds)

        if session_name is None or remote_pcap_path is None:
            raise RuntimeError("tcpdump session state was not initialized.")

        local_path = stop_settle_and_download(
            ssh_transport=ssh_transport,
            config=config,
            session_name=session_name,
            remote_pcap_path=remote_pcap_path,
            output_dir=output_dir,
        )
        LOG.info("Saved %s", local_path)
        return local_path
    except Exception:
        best_effort_cleanup(config, config_dir, session_name, remote_pcap_path)
        raise


def main() -> int:
    configure_logging()
    args = parse_args()
    config_path = Path(args.config).expanduser().resolve()
    config_dir = config_path.parent
    base_output_dir = resolve_output_dir(args.output_dir)
    start_iteration = args.start_iteration
    end_iteration = args.end_iteration
    run_count = end_iteration - start_iteration + 1

    try:
        validate_iteration_range(start_iteration, end_iteration)
        config = load_config(config_path)
        config["start_iteration"] = start_iteration
        config["iterations"] = end_iteration
        steps = [
            CaptureStep("aac_step1_direct", 1, False),
            CaptureStep("aac_step2_ssheasy", 2, True),
            CaptureStep("aac_step3_direct", 3, False),
        ]

        for iteration in range(start_iteration, end_iteration + 1):
            iteration_output_dir = base_output_dir / str(iteration)
            iteration_output_dir.mkdir(parents=True, exist_ok=True)

            iteration_config = apply_requested_overrides(
                config,
                output_dir=iteration_output_dir,
                duration_seconds=args.duration_seconds,
            )

            if iteration == start_iteration:
                validate_config(iteration_config, config_dir)
                remote_preflight(build_ssh_transport(iteration_config, config_dir))

            LOG.info(
                "Starting iteration %s/%s (%s of %s runs)",
                iteration,
                end_iteration,
                iteration - start_iteration + 1,
                run_count,
            )
            record_public_ip(iteration_config, config_dir, iteration)

            for step in steps:
                run_capture_step(
                    base_config=iteration_config,
                    config_dir=config_dir,
                    step=step,
                    duration_seconds=args.duration_seconds,
                    headful=args.headful,
                    output_dir=iteration_output_dir,
                )

    except ConfigError as exc:
        LOG.error("%s", exc)
        return 2
    except Exception as exc:
        LOG.exception("Capture workflow failed: %s", exc)
        return 1

    LOG.info(
        "Completed iterations %s through %s (%s runs)",
        start_iteration,
        end_iteration,
        run_count,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
