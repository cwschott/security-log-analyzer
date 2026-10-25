from datetime import datetime
from collections import defaultdict


def parse_log_line(line):
    parts = line.strip().split()

    if len(parts) != 5:
        return None

    timestamp_text = f"{parts[0]} {parts[1]}"
    event_type = parts[2]
    username = parts[3].split("=", 1)[1]
    ip_address = parts[4].split("=", 1)[1]

    return {
        "timestamp": datetime.strptime(
            timestamp_text,
            "%Y-%m-%d %H:%M:%S"
        ),
        "event_type": event_type,
        "username": username,
        "ip_address": ip_address,
    }

def load_events(filename):
    events = []

    with open(filename, "r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            if not line.strip():
                continue

            try:
                event = parse_log_line(line)

                if event is not None:
                    events.append(event)
                else:
                    print(f"Skipping malformed line {line_number}")

            except (ValueError, IndexError):
                print(f"Skipping malformed line {line_number}")

    return events

def detect_suspicious_activity(events, threshold=5):
    activity_by_ip = defaultdict(
        lambda: {
            "failures": [],
            "successful_logins": [],
            "usernames": set(),
        }
    )

    for event in events:
        ip_address = event["ip_address"]
        activity = activity_by_ip[ip_address]

        if event["event_type"] == "LOGIN_FAILED":
            activity["failures"].append(event)
            activity["usernames"].add(event["username"])

        elif event["event_type"] == "LOGIN_SUCCESS":
            activity["successful_logins"].append(event)

    alerts = []

    for ip_address, activity in activity_by_ip.items():
        failures = activity["failures"]

        if len(failures) >= threshold:
            last_failure = max(
                event["timestamp"] for event in failures
            )

            later_successes = [
                event
                for event in activity["successful_logins"]
                if event["timestamp"] > last_failure
            ]

            alerts.append(
                {
                    "ip_address": ip_address,
                    "failure_count": len(failures),
                    "usernames": sorted(activity["usernames"]),
                    "first_failure": min(
                        event["timestamp"] for event in failures
                    ),
                    "last_failure": last_failure,
                    "successful_login_afterward": bool(later_successes),
                }
            )

    return alerts

def print_alerts(alerts):
    if not alerts:
        print("\nNo suspicious activity detected.")
        return

    print(f"\nDetected {len(alerts)} suspicious IP address(es).")

    for alert in alerts:
        usernames = ", ".join(alert["usernames"])

        if alert["successful_login_afterward"]:
            successful_login = "Yes"
        else:
            successful_login = "No"

        print("\n" + "=" * 50)
        print("ALERT: Possible brute-force activity")
        print(f"IP address: {alert['ip_address']}")
        print(f"Failed attempts: {alert['failure_count']}")
        print(f"Targeted accounts: {usernames}")
        print(
            "Time range: "
            f"{alert['first_failure']:%Y-%m-%d %H:%M:%S} to "
            f"{alert['last_failure']:%Y-%m-%d %H:%M:%S}"
        )
        print(f"Successful login afterward: {successful_login}")

        if alert["successful_login_afterward"]:
            print("Severity: HIGH")
            print(
                "Recommendation: Investigate the account and "
                "source IP immediately."
            )
        else:
            print("Severity: MEDIUM")
            print(
                "Recommendation: Review the source IP and "
                "consider temporarily blocking it."
            )

def main():
    events = load_events("sample_auth.log")
    alerts = detect_suspicious_activity(events, threshold=5)

    print(f"Analyzed {len(events)} authentication events.")
    print_alerts(alerts)


if __name__ == "__main__":
    main()