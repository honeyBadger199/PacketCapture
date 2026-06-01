# WebSSH + tcpdump Runner

This folder contains a Python script that automates the exact loop you described:

1. SSH to the VM.
2. Start `tcpdump` inside a detached `tmux` session.
3. Disconnect while keeping `tmux` alive.
4. Open WebSSH in the browser, connect to the VM, and keep the session open.
5. Wait 10 seconds, reconnect to the VM, stop `tcpdump`, and download the `.pcap`.
6. Repeat for the configured number of iterations.

## Files

- `ssheasy_capture_runner.py`: main runner
- `capture_config.example.json`: sample config you can copy and fill in

## Dependencies

The script uses:

- local `ssh` and `scp` from the OpenSSH client
- `sshpass` for password-based direct SSH control
- `playwright` for browser automation
- a Playwright browser install, with bundled Firefox as the default

Install Python packages if needed:

```bash
pip install -r tcpdump_onlineSSH/requirements.txt
```

Install the default Playwright browser once:

```bash
python3 -m playwright install firefox
```

If your `vm` section uses `password` instead of `private_key_path`, install `sshpass` locally too.

## Config

Create a local config file next to the example:

```bash
cp tcpdump_onlineSSH/capture_config.example.json tcpdump_onlineSSH/capture_config.local.json
```

Then edit these sections:

- `vm`: direct SSH access used to start and stop `tcpdump`
- `capture`: `tcpdump` interface, extra flags, remote filename template
- `online_ssh`: WebSSH URL and the target SSH credentials used inside the website
- `local`: where downloaded `.pcap` files should be saved

The sample config is set up for a long run:

- `iterations: 50`
- `start_iteration: 14`
- remote files named `capture5_014.pcap` through `capture5_050.pcap`
- local downloads saved into `tcpdump_onlineSSH/pcaps/`
- public IPs logged to `tcpdump_onlineSSH/pcaps/public_ip_log.txt`

Your prompt mentioned both "stay there for 2 minutes" and "wait for 1 minute". The script keeps this configurable through `timing.online_session_seconds`. Set it to `120` for 2 minutes or `60` for 1 minute.

## Notes

- The script assumes `tmux` and `tcpdump` already exist on the VM.
- The direct control path now uses local OpenSSH commands instead of Paramiko, so `ssh` and `scp` must be available on your machine.
- If you use `vm.password` for the direct SSH login, `sshpass` must be installed locally. If you use `vm.private_key_path`, `sshpass` is not required.
- If `tcpdump` needs `sudo`, set `capture.require_sudo` to `true` and provide `vm.sudo_password`.
- Because your filter includes `port 22`, the runner now waits for the remote capture to stop cleanly and downloads a fixed snapshot copy so the `scp` transfer does not grow the same `.pcap` while copying.
- If WebSSH shows an extra host-key confirmation or disconnect button, fill the optional Playwright selectors:
  - `accept_host_key_selector`
  - `disconnect_button_selector`
- On this machine, Snap Chromium is not usable from Playwright. The sample config defaults to Playwright's bundled Firefox. Leave `browser_executable` as `null` unless you have a known-good browser binary.
- The browser step supports two direct-connect URL formats through `online_ssh.url_style`:
  - `connect_params`: `/connect?host=...&port=...&user=...&password=...`
  - `webssh_query`: `/?hostname=...&port=...&username=...&password=<base64 password>`

For `https://webssh.webhorizon.net/`, use:

```text
base_url: https://webssh.webhorizon.net/
url_style: webssh_query
connect_path: /
```

## Run

```bash
python3 tcpdump_onlineSSH/ssheasy_capture_runner.py \
  --config tcpdump_onlineSSH/capture_config.local.json
```

For visible browser debugging:

```bash
python3 tcpdump_onlineSSH/ssheasy_capture_runner.py \
  --config tcpdump_onlineSSH/capture_config.local.json \
  --headful
```

## What gets downloaded

Each iteration creates a uniquely named `.pcap` on the VM, then downloads it into `tcpdump_onlineSSH/pcaps/` by default.

The runner also appends one line per iteration to `tcpdump_onlineSSH/pcaps/public_ip_log.txt` with the local date/time, iteration number, and detected public IP.
