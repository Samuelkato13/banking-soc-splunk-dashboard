import csv
import random
from datetime import datetime, timedelta

TOTAL_LOGS = 5000
START_TIME = datetime.now() - timedelta(hours=8)
OUTPUT_FILE = "bank_soc_logs.csv"

SYSTEM_CONFIG = {
    "ATM": {"ports": [443, 22], "protocols": ["TCP"]},
    "MobileApp": {"ports": [443], "protocols": ["TCP"]},
    "CoreBanking": {"ports": [443, 22, 3306], "protocols": ["TCP"]},
    "WebPortal": {"ports": [443, 80], "protocols": ["TCP"]},
    "InternalAPI": {"ports": [443, 8080], "protocols": ["TCP"]},
}

NORMAL_EVENT_WEIGHTS = {
    "LOGIN_SUCCESS": 0.22,
    "DATA_REQUEST": 0.36,
    "TRANSFER": 0.18,
    "PING": 0.24,
}

ATTACKER_IPS = ["185.143.223.10", "102.89.34.55", "45.67.12.99", "91.240.118.77"]
INTERNAL_RANGES = ["10.20", "10.21", "172.16", "172.20", "192.168"]
PUBLIC_BANK_EDGE = "197.210"


def weighted_choice(weight_map):
    keys = list(weight_map.keys())
    weights = list(weight_map.values())
    return random.choices(keys, weights=weights, k=1)[0]


def random_private_ip():
    net = random.choice(INTERNAL_RANGES)
    return f"{net}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def random_public_ip():
    if random.random() < 0.05:
        return f"{PUBLIC_BANK_EDGE}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def human_traffic_multiplier(ts):
    hour = ts.hour
    if 8 <= hour <= 18:
        return 1.0
    if 19 <= hour <= 22:
        return 0.75
    return 0.45


def random_normal_row(ts):
    system = random.choices(
        ["WebPortal", "MobileApp", "InternalAPI", "CoreBanking", "ATM"],
        weights=[0.3, 0.22, 0.2, 0.18, 0.1],
        k=1,
    )[0]
    config = SYSTEM_CONFIG[system]

    # External clients mostly hit portal/app, internal systems are mostly east-west traffic.
    if system in ("WebPortal", "MobileApp"):
        src_ip = random_public_ip()
        dest_ip = f"{PUBLIC_BANK_EDGE}.{random.randint(1, 30)}.{random.randint(1, 254)}"
    else:
        src_ip = random_private_ip()
        dest_ip = random_private_ip()

    protocol = random.choice(config["protocols"])
    port = random.choice(config["ports"])

    event_weights = dict(NORMAL_EVENT_WEIGHTS)
    if 0 <= ts.hour <= 5:
        event_weights["PING"] += 0.20
        event_weights["TRANSFER"] -= 0.06
    else:
        event_weights["TRANSFER"] += 0.06

    event = weighted_choice(event_weights)
    action = "ALLOW"

    # Small natural failure rate in real systems.
    if random.random() < 0.015:
        action = "DENY"
        event = "LOGIN_FAILED"

    return [ts.strftime("%Y-%m-%d %H:%M:%S"), src_ip, dest_ip, protocol, port, system, action, event]


def brute_force_rows(base_ts):
    rows = []
    attacker = random.choice(ATTACKER_IPS)
    target = f"{PUBLIC_BANK_EDGE}.{random.randint(2, 20)}.{random.randint(1, 254)}"
    burst = random.randint(15, 40)
    for n in range(burst):
        rows.append(
            [
                (base_ts + timedelta(seconds=n * random.randint(2, 6))).strftime("%Y-%m-%d %H:%M:%S"),
                attacker,
                target,
                "TCP",
                random.choice([22, 443, 3389]),
                random.choice(["WebPortal", "InternalAPI"]),
                "DENY",
                "LOGIN_FAILED",
            ]
        )
    return rows


def port_scan_rows(base_ts):
    rows = []
    attacker = random.choice(ATTACKER_IPS)
    target = f"{PUBLIC_BANK_EDGE}.{random.randint(2, 20)}.{random.randint(1, 254)}"
    candidate_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]
    for n, port in enumerate(random.sample(candidate_ports, k=random.randint(7, 12))):
        rows.append(
            [
                (base_ts + timedelta(seconds=n)).strftime("%Y-%m-%d %H:%M:%S"),
                attacker,
                target,
                "TCP",
                port,
                random.choice(["WebPortal", "InternalAPI"]),
                "DENY",
                "PING",
            ]
        )
    return rows


def suspicious_transfer_rows(base_ts):
    rows = []
    compromised = random_public_ip()
    core_target = random_private_ip()
    burst = random.randint(8, 20)
    for n in range(burst):
        rows.append(
            [
                (base_ts + timedelta(seconds=n * random.randint(5, 12))).strftime("%Y-%m-%d %H:%M:%S"),
                compromised,
                core_target,
                "TCP",
                443,
                random.choice(["MobileApp", "CoreBanking"]),
                random.choice(["ALLOW", "DENY"]),
                "TRANSFER",
            ]
        )
    return rows


def main():
    rows = []
    ts = START_TIME

    while len(rows) < TOTAL_LOGS:
        ts += timedelta(seconds=random.randint(1, 3))

        attack_probability = 0.04 * human_traffic_multiplier(ts)
        if random.random() < attack_probability:
            campaign_type = random.choices(
                ["bruteforce", "scan", "transfer-abuse"], weights=[0.55, 0.25, 0.20], k=1
            )[0]
            if campaign_type == "bruteforce":
                rows.extend(brute_force_rows(ts))
            elif campaign_type == "scan":
                rows.extend(port_scan_rows(ts))
            else:
                rows.extend(suspicious_transfer_rows(ts))
            continue

        rows.append(random_normal_row(ts))

    rows = rows[:TOTAL_LOGS]
    rows.sort(key=lambda r: r[0])

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file_handle:
        writer = csv.writer(file_handle)
        writer.writerow(["timestamp", "src_ip", "dest_ip", "protocol", "port", "system", "action", "event"])
        writer.writerows(rows)

    print(f"Realistic dataset generated: {OUTPUT_FILE} ({len(rows)} rows)")


if __name__ == "__main__":
    main()