#!/usr/bin/env python3
"""
Monitor Drift attacker holding wallets for nonce/balance changes.
Polls every 60 seconds. Prints alerts when state changes.
Run: python3 scripts/monitor_holding_wallets.py
"""
import requests
import time
import sys
from datetime import datetime

RPC = "https://ethereum-rpc.publicnode.com"

WALLETS = {
    "0xAa843eD65C1f061F111B5289169731351c5e57C1": {
        "name": "Holding 1 (25,715 ETH)",
        "last_nonce": 0,
        "last_balance": 25714.6921,
    },
    "0xbDdAE987FEe930910fCC5aa403D5688fB440561B": {
        "name": "Holding 2 (23,097 ETH)",
        "last_nonce": 0,
        "last_balance": 23096.6570,
    },
}

POLL_INTERVAL = 60


def rpc(method, params):
    r = requests.post(RPC, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=15)
    return r.json().get("result")


def check():
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    for addr, info in WALLETS.items():
        nonce = int(rpc("eth_getTransactionCount", [addr, "latest"]) or "0x0", 16)
        bal = int(rpc("eth_getBalance", [addr, "latest"]) or "0x0", 16) / 1e18

        alerts = []
        if nonce != info["last_nonce"]:
            alerts.append(f"NONCE CHANGED {info['last_nonce']} -> {nonce}")
            info["last_nonce"] = nonce
        if abs(bal - info["last_balance"]) > 0.01:
            alerts.append(f"BALANCE CHANGED {info['last_balance']:.4f} -> {bal:.4f} ETH")
            info["last_balance"] = bal

        if alerts:
            for a in alerts:
                print(f"\n*** ALERT [{now}] {info['name']}: {a} ***", flush=True)
        else:
            print(f"[{now}] {info['name']}: nonce={nonce} bal={bal:.4f} ETH — no change", flush=True)


if __name__ == "__main__":
    print("Drift holding wallet monitor started. Ctrl+C to stop.\n", flush=True)
    try:
        while True:
            check()
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
