#!/usr/bin/env python3
"""
Link Check: will your drone obey MAVLink commands from anyone?

It checks for the problem behind CVE-2026-1579: a PX4 or ArduPilot drone that
accepts unsigned MAVLink messages lets anyone who can reach its radio link send
it commands. The fix is MAVLink 2 message signing.

What it does, in plain English:
  1. Connects to your drone (or simulator) and waits for its heartbeat.
  2. Listens for a few seconds: are the drone's own messages signed?
  3. Sends ONE harmless, read-only, unsigned request: "what is your first setting?"
     If the drone answers, it accepts unsigned messages: EXPOSED.
     If it stays silent while signing its own messages: PROTECTED.

It never arms, moves, reboots, uploads missions or changes a setting.
Only test drones you own or have written permission to test.

Exit codes: 0 PROTECTED, 2 EXPOSED, 3 UNCLEAR, 1 could not run.
"""

import argparse
import json
import os
import sys
import time

# pymavlink picks MAVLink 1 or 2 when it is imported, so set this first.
os.environ["MAVLINK20"] = "1"

try:
    from pymavlink import mavutil
except ImportError:  # pragma: no cover - friendly message for beginners
    sys.exit("pymavlink is not installed. Run:  pip3 install pymavlink")

VERSION = "0.1.0"
MAV = mavutil.mavlink

ARDUPILOT_DOCS = "https://ardupilot.org/copter/docs/common-MAVLink2-signing.html"
ADVISORY = "https://nvd.nist.gov/vuln/detail/CVE-2026-1579"

# We ask for parameter number 0 by position, not by name, because names change
# between firmware versions (ArduPilot renamed SYSID_THISMAV to MAV_SYSID).
# Reading a parameter changes nothing on the drone.
PARAM_INDEX = 0


# --------------------------------------------------------------------------- helpers

class Style:
    """Tiny helper for colored text. Colors switch off when output is not a terminal."""

    def __init__(self, enabled):
        self.enabled = enabled

    def _wrap(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def red(self, text):
        return self._wrap("1;31", text)

    def green(self, text):
        return self._wrap("1;32", text)

    def yellow(self, text):
        return self._wrap("1;33", text)

    def bold(self, text):
        return self._wrap("1", text)


def autopilot_name(code):
    if code == MAV.MAV_AUTOPILOT_ARDUPILOTMEGA:
        return "ArduPilot"
    if code == MAV.MAV_AUTOPILOT_PX4:
        return "PX4"
    entry = MAV.enums["MAV_AUTOPILOT"].get(code)
    return entry.name.replace("MAV_AUTOPILOT_", "").title() if entry else f"Unknown ({code})"


def vehicle_name(code):
    entry = MAV.enums["MAV_TYPE"].get(code)
    if not entry:
        return f"Unknown ({code})"
    return entry.name.replace("MAV_TYPE_", "").replace("_", " ").title()


def is_mavlink2(msg):
    buf = msg.get_msgbuf()
    return bool(buf) and buf[0] == MAV.PROTOCOL_MARKER_V2


def is_signed(msg):
    header = msg.get_header()
    return bool(getattr(header, "incompat_flags", 0) & MAV.MAVLINK_IFLAG_SIGNED)


def looks_like_usb(connect):
    """ArduPilot skips signing checks on USB, so a USB test can't tell you much."""
    c = connect.lower()
    return c.startswith("/dev/") or c.startswith("com") or "usb" in c


def confirm_permission(args, style):
    if args.yes or not sys.stdin.isatty():
        return True
    print(style.bold("Only test drones you own or have written permission to test."))
    answer = input("Do you own this drone, or have permission to test it? [y/N] ").strip().lower()
    return answer in ("y", "yes")


# --------------------------------------------------------------------------- the three steps

def connect(args):
    kwargs = dict(
        source_system=args.source_system,
        source_component=MAV.MAV_COMP_ID_MISSIONPLANNER,
        autoreconnect=False,
    )
    if args.baud:
        kwargs["baud"] = args.baud
    return mavutil.mavlink_connection(args.connect, **kwargs)


def wait_for_vehicle(conn, timeout):
    """Wait for a heartbeat from an autopilot (ignore other ground stations)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = conn.recv_match(type="HEARTBEAT", blocking=True, timeout=max(0.1, deadline - time.time()))
        if msg is None:
            continue
        if msg.autopilot == MAV.MAV_AUTOPILOT_INVALID or msg.type == MAV.MAV_TYPE_GCS:
            continue
        return msg
    return None


def check_signing(conn, sysid, seconds, first_msg):
    """Check 1: count how many of the drone's MAVLink 2 messages carry a signature."""
    counts = {"signed": 0, "unsigned": 0, "mavlink1": 0}

    def tally(msg):
        if msg.get_srcSystem() != sysid:
            return
        if not is_mavlink2(msg):
            counts["mavlink1"] += 1
        elif is_signed(msg):
            counts["signed"] += 1
        else:
            counts["unsigned"] += 1

    tally(first_msg)
    deadline = time.time() + seconds
    while time.time() < deadline:
        msg = conn.recv_match(blocking=True, timeout=max(0.1, deadline - time.time()))
        if msg is not None and msg.get_type() != "BAD_DATA":
            tally(msg)

    total = counts["signed"] + counts["unsigned"] + counts["mavlink1"]
    if counts["signed"] and not (counts["unsigned"] or counts["mavlink1"]):
        result = "SIGNED"
    elif counts["signed"]:
        result = "MIXED"
    else:
        result = "NOT SIGNED"
    return {"result": result, "total": total, **counts}


def check_unsigned_request(conn, sysid, compid, wait, tries):
    """Check 2: send one unsigned, read-only parameter request and see if the drone answers."""
    for attempt in range(1, tries + 1):
        conn.mav.param_request_read_send(sysid, compid, b"", PARAM_INDEX)
        deadline = time.time() + wait
        while time.time() < deadline:
            msg = conn.recv_match(type="PARAM_VALUE", blocking=True, timeout=max(0.1, deadline - time.time()))
            if msg is None or msg.get_srcSystem() != sysid or msg.param_index != PARAM_INDEX:
                continue
            name = msg.param_id if isinstance(msg.param_id, str) else msg.param_id.decode(errors="replace")
            return {"answered": True, "attempts": attempt, "param": name.rstrip("\x00"), "value": msg.param_value}
    return {"answered": False, "attempts": tries, "param": None, "value": None}


def verdict(signing, request):
    if request["answered"]:
        return "EXPOSED", "The drone answered an unsigned message. Anyone who can reach this link can send it commands."
    if signing["signed"]:
        return "PROTECTED", "The drone ignored an unsigned message and signs its own. Message signing is on."
    return ("UNCLEAR", "The drone didn't answer, but its messages aren't signed either. The link may be one-way, "
            "busy or lossy. Check the connection and run Link Check again.")


# --------------------------------------------------------------------------- report

def fix_steps(autopilot):
    ardupilot = [
        "Connect over USB or another link you trust.",
        "Mission Planner: SETUP > Advanced > MAVLink Signing, then add a key.",
        "Or in MAVProxy, type:  signing setup <a long passphrase>",
        "Give the same key to every ground station that flies this drone.",
        f"Guide: {ARDUPILOT_DOCS}",
    ]
    px4 = [
        "From a trusted link, send SETUP_SIGNING with a 32-byte secret key (your ground station or a script).",
        "PX4 then rejects unsigned messages on its MAVLink links and keeps the key on the SD card.",
        "Give the same key to every ground station that flies this drone.",
        f"Advisory and fix: {ADVISORY}",
    ]
    if autopilot == MAV.MAV_AUTOPILOT_PX4:
        return px4
    if autopilot == MAV.MAV_AUTOPILOT_ARDUPILOTMEGA:
        return ardupilot
    return ardupilot + px4


def print_report(report, style):
    v = report["vehicle"]
    s = report["check_signed"]
    r = report["check_unsigned_request"]
    color = {"EXPOSED": style.red, "PROTECTED": style.green, "UNCLEAR": style.yellow}[report["verdict"]]

    print()
    print(style.bold("Link Check report"))
    print(f"  Connection   {report['connection']}")
    print(f"  Vehicle      {v['type']}, {v['autopilot']}, system {v['system_id']}")
    print(f"  Check 1      Messages from the drone: {s['result']} "
          f"({s['signed']} signed, {s['unsigned']} unsigned, {s['mavlink1']} MAVLink 1)")
    answered = f"ANSWERED ({r['param']} = {r['value']:g})" if r["answered"] else "NO ANSWER"
    print(f"  Check 2      Unsigned read of parameter #{PARAM_INDEX}: {answered}")
    print()
    print("  " + color(report["verdict"]) + "  " + report["explanation"])
    if report.get("usb_warning"):
        print()
        print(style.yellow("  Note: ") + "this looks like a USB connection. ArduPilot doesn't check signatures on USB, "
              "so test over your telemetry radio or network link instead.")
    if report["verdict"] == "EXPOSED":
        print()
        print(style.bold("  How to fix it"))
        for i, step in enumerate(report["fix"], 1):
            print(f"    {i}. {step}")
    print()


# --------------------------------------------------------------------------- main

def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="link_check",
        description="Check whether a drone you own accepts unsigned MAVLink commands (CVE-2026-1579). Read-only.",
    )
    p.add_argument("--connect", default="tcp:127.0.0.1:5762",
                   help="where the drone is: tcp:HOST:PORT, udpin:0.0.0.0:14550, or a serial port "
                        "(default: tcp:127.0.0.1:5762, the ArduPilot simulator's signed-checked port)")
    p.add_argument("--baud", type=int, default=0, help="baud rate for serial ports, for example 57600")
    p.add_argument("--timeout", type=float, default=10, help="seconds to wait for a heartbeat (default 10)")
    p.add_argument("--listen", type=float, default=5, help="seconds to watch for signed messages (default 5)")
    p.add_argument("--wait", type=float, default=3, help="seconds to wait for an answer to the request (default 3)")
    p.add_argument("--tries", type=int, default=2, choices=range(1, 6), metavar="1-5",
                   help="how many times to send the read-only request if there's no answer (default 2)")
    p.add_argument("--source-system", type=int, default=254,
                   help="system ID Link Check uses for itself (default 254, so it won't clash with your ground station)")
    p.add_argument("--json", action="store_true", help="print the report as JSON")
    p.add_argument("--no-color", action="store_true", help="plain text output")
    p.add_argument("--yes", action="store_true", help="skip the permission question (you own or may test this drone)")
    p.add_argument("--version", action="version", version=f"Link Check {VERSION}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    style = Style(enabled=sys.stdout.isatty() and not args.no_color and not args.json)
    say = (lambda *a: None) if args.json else print

    if not confirm_permission(args, style):
        print("Stopped. Only test drones you own or have permission to test.")
        return 1

    say(f"Connecting to {args.connect} ...")
    try:
        conn = connect(args)
    except Exception as exc:  # network errors, bad serial port names, and so on
        print(f"Could not connect to {args.connect}: {exc}", file=sys.stderr)
        print("Is the drone or simulator running? Check the address and port "
              "(the ArduPilot simulator uses port 5762 for this test).", file=sys.stderr)
        return 1

    heartbeat = wait_for_vehicle(conn, args.timeout)
    if heartbeat is None:
        print(f"No drone heartbeat on {args.connect} within {args.timeout:g} seconds. "
              "Is the drone or simulator running, and is the address right?", file=sys.stderr)
        return 1

    sysid, compid = heartbeat.get_srcSystem(), heartbeat.get_srcComponent()
    say(f"Found {vehicle_name(heartbeat.type)} running {autopilot_name(heartbeat.autopilot)} (system {sysid}).")

    say(f"Check 1: listening {args.listen:g} seconds for signed messages ...")
    signing = check_signing(conn, sysid, args.listen, heartbeat)

    say(f"Check 2: sending one unsigned, read-only request for parameter #{PARAM_INDEX} ...")
    request = check_unsigned_request(conn, sysid, compid, args.wait, args.tries)
    conn.close()

    result, explanation = verdict(signing, request)
    report = {
        "tool": "Link Check",
        "version": VERSION,
        "connection": args.connect,
        "vehicle": {
            "type": vehicle_name(heartbeat.type),
            "autopilot": autopilot_name(heartbeat.autopilot),
            "system_id": sysid,
            "component_id": compid,
        },
        "check_signed": signing,
        "check_unsigned_request": request,
        "verdict": result,
        "explanation": explanation,
        "usb_warning": looks_like_usb(args.connect),
        "fix": fix_steps(heartbeat.autopilot) if result == "EXPOSED" else [],
        "reference": ADVISORY,
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report, style)

    return {"PROTECTED": 0, "EXPOSED": 2, "UNCLEAR": 3}[result]


if __name__ == "__main__":
    sys.exit(main())
