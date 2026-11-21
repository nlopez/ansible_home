#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
"""Inventory the devices on both sites and write two CSVs.

Reads each OPNsense gateway's ARP table, Dnsmasq leases and reservations,
resolves PTR names against the gateway, and looks up OUI vendors.

  device-inventory.csv  everything, with vendor and gaps, for reading
  ip-enrichment.csv     ip,tags for Datadog NetFlow > Configuration > Add Enrichment

Uploading an enrichment CSV replaces the previous one, so always upload the
full file. The OPNsense API credentials come from 1Password via `op`.
"""
import argparse
import csv
import json
import subprocess
from pathlib import Path

VAULT = "evjh25ux2mnoufaut6qhvm2pdi"
ACCOUNT = "my.1password.com"
SITES = {
    "lga1": {"gateway": "gw.lga1.radoncanyon.com", "api_item": "bf3fyn3ojaajnozdbobkhtboli"},
    "lga2": {"gateway": "gw.lga2.radoncanyon.com", "api_item": "whuw4bp5c3lbzv2hmq4nja7qvq"},
}
OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_CACHE = Path.home() / ".cache" / "ieee-oui.csv"


def op(field, item):
    return subprocess.run(
        ["op", "read", f"op://{VAULT}/{item}/{field}", "--account", ACCOUNT],
        check=True, capture_output=True, text=True).stdout.strip()


def api(site, path):
    cfg = SITES[site]
    creds = f"{op('key', cfg['api_item'])}:{op('credential', cfg['api_item'])}"
    # curl verifies against the system trust store, which uv's bundled Python lacks.
    # The credentials go in on stdin to keep them out of the process list.
    out = subprocess.run(["curl", "-fsS", "--max-time", "30", "--config", "-", f"https://{cfg['gateway']}{path}"],
                         input=f'user = "{creds}"\n', check=True, capture_output=True, text=True).stdout
    return json.loads(out)["rows"]


def load_oui():
    if not OUI_CACHE.exists():
        OUI_CACHE.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["curl", "-fsSL", "-o", OUI_CACHE, OUI_URL], check=True)
    with open(OUI_CACHE, encoding="utf-8") as f:
        return {r["Assignment"].upper(): r["Organization Name"] for r in csv.DictReader(f)}


def ptr(ip, gateway):
    out = subprocess.run(["dig", "+short", "+time=2", "+tries=1", "-x", ip, f"@{gateway}"],
                         capture_output=True, text=True).stdout.split()
    return out[0].rstrip(".").split(".")[0] if out else ""


def vendor(mac, oui):
    if int(mac.split(":")[0], 16) & 2:
        return "(private MAC)"
    return oui.get(mac.replace(":", "")[:6].upper(), "(unknown OUI)")


def collect(site, oui):
    gw = SITES[site]["gateway"]
    leases = {l["address"]: l for l in api(site, "/api/dnsmasq/leases/search")}
    reserved = {h["hwaddr"].lower(): h["host"] for h in api(site, "/api/dnsmasq/settings/search_host") if h["hwaddr"]}
    devices = {}
    for a in api(site, "/api/diagnostics/interface/search_arp"):
        if a["ip"].startswith("192.168."):
            devices[a["ip"]] = {"mac": a["mac"].lower(), "network": a["intf_description"].lower()}
    for ip, l in leases.items():
        devices.setdefault(ip, {"mac": l["hwaddr"].lower(), "network": "lease only"})
    rows = []
    for ip, d in sorted(devices.items(), key=lambda kv: tuple(map(int, kv[0].split(".")))):
        lease_name = leases.get(ip, {}).get("hostname", "")
        lease_name = "" if lease_name == "*" else lease_name
        rows.append({"site": site, "ip": ip, "mac": d["mac"], "vendor": vendor(d["mac"], oui),
                     "name": ptr(ip, gw) or lease_name or reserved.get(d["mac"], ""),
                     "reserved": "Y" if d["mac"] in reserved else "", "network": d["network"]})
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("-o", "--out", type=Path, default=Path.home() / "Desktop", help="output directory")
    out = p.parse_args().out
    oui = load_oui()
    rows = [r for site in SITES for r in collect(site, oui)]
    with open(out / "device-inventory.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    with open(out / "ip-enrichment.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "tags"])
        for r in rows:
            tags = [f"site:{r['site']}"]
            if r["name"]:
                tags.append(f"hostname:{r['name']}")
            if r["network"] != "lease only":
                tags.append(f"network:{r['network']}")
            w.writerow([r["ip"], ",".join(tags)])
    unnamed = [r for r in rows if not r["name"]]
    print(f"{len(rows)} devices, {len(unnamed)} unnamed -> {out}")
    for r in unnamed:
        print(f"  {r['site']} {r['ip']:<16}{r['mac']}  {r['vendor']}  ({r['network']})")


if __name__ == "__main__":
    main()
