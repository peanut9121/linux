from collections import Counter
from pathlib import Path

LOG_PATH = Path("/var/log/unix-cyber-lab/events.log")


def parse_field(line, field):
    marker = f"{field}="
    if marker not in line:
        return "unknown"
    return line.split(marker, 1)[1].split(" ", 1)[0].strip()


def main():
    if not LOG_PATH.exists():
        print("[defender] no events found yet")
        return

    lines = [line.strip() for line in LOG_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    event_types = Counter(parse_field(line, "type") for line in lines)
    failed_logins = [line for line in lines if "type=login_attempt" in line and "result=failed" in line]
    vulnerability_accesses = [line for line in lines if "type=vulnerability_access" in line]
    configuration_changes = [line for line in lines if "type=configuration_changed" in line]
    successful_exploits = [line for line in lines if "type=exploit_success" in line]

    print("[defender] event summary")
    for event_type, count in event_types.items():
        print(f"- {event_type}: {count}")

    if len(failed_logins) >= 3:
        print("[alert] multiple failed login attempts detected")
        print("[suggestion] check source IP, review account policy, and consider firewall rules")
    if vulnerability_accesses:
        print("[alert] known vulnerable endpoint accessed")
        print("[suggestion] remove exposed debug, backup, and admin endpoints")
    if configuration_changes:
        print("[alert] configuration integrity changed")
        print("[suggestion] restore the file and restrict write permissions")
    if successful_exploits:
        print(f"[alert] {len(successful_exploits)} controlled exploit actions succeeded")
        print("[suggestion] review the affected resource and compare its before/after state")
    if not failed_logins and not vulnerability_accesses and not configuration_changes and not successful_exploits:
        print("[defender] no high-risk pattern detected")


if __name__ == "__main__":
    main()
