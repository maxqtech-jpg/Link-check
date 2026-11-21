#!/usr/bin/env python3
"""
A pretend drone for testing Link Check on your own computer, no simulator needed.

It listens on a TCP port, sends a heartbeat every second, and answers requests
for its settings (parameters), like a real drone would.

  python3 fake_drone.py                       # signing OFF: Link Check should say EXPOSED
  python3 fake_drone.py --signing mypassword  # signing ON:  Link Check should say PROTECTED

With --signing it does what MAVProxy's "signing setup" does to a real drone:
it signs everything it sends and ignores any message without a valid signature.

Stop it with Ctrl+C.
"""

import argparse
import hashlib
import os
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402

MAV = mavutil.mavlink


def passphrase_to_key(passphrase):
    """Same as MAVProxy: the 32-byte key is the SHA-256 hash of the passphrase."""
    return hashlib.sha256(passphrase.encode("utf-8")).digest()


def main():
    p = argparse.ArgumentParser(description="Pretend drone for testing Link Check.")
    p.add_argument("--port", type=int, default=5762, help="TCP port to listen on (default 5762)")
    p.add_argument("--signing", metavar="PASSPHRASE", help="turn on MAVLink 2 signing with this passphrase")
    p.add_argument("--autopilot", choices=["ardupilot", "px4"], default="ardupilot")
    args = p.parse_args()

    autopilot = MAV.MAV_AUTOPILOT_PX4 if args.autopilot == "px4" else MAV.MAV_AUTOPILOT_ARDUPILOTMEGA
    # A few pretend settings. Index 0 is what Link Check asks for.
    params = [("FORMAT_VERSION", 120.0), ("MAV_SYSID", 1.0)] if args.autopilot == "ardupilot" \
        else [("MAV_SYS_ID", 1.0), ("MAV_COMP_ID", 1.0)]
    sysid = 1

    conn = mavutil.mavlink_connection(f"tcpin:0.0.0.0:{args.port}", source_system=sysid, source_component=1)
    if args.signing:
        # No allow_unsigned_callback: unsigned messages are dropped, like a real signed drone.
        conn.setup_signing(passphrase_to_key(args.signing), sign_outgoing=True)

    mode = "ON (unsigned messages are ignored)" if args.signing else "OFF (it will answer anyone)"
    print(f"Pretend {args.autopilot} drone listening on port {args.port}. Signing {mode}. Ctrl+C to stop.")

    next_heartbeat = 0.0
    try:
        while True:
            now = time.time()
            if now >= next_heartbeat:
                conn.mav.heartbeat_send(MAV.MAV_TYPE_QUADROTOR, autopilot, 0, 0, MAV.MAV_STATE_STANDBY)
                next_heartbeat = now + 1.0

            msg = conn.recv_match(blocking=True, timeout=0.2)
            if msg is None or msg.get_type() == "BAD_DATA":
                continue
            if msg.get_type() == "PARAM_REQUEST_READ":
                name = msg.param_id.rstrip("\x00")
                for index, (pname, value) in enumerate(params):
                    if msg.param_index == index or (msg.param_index < 0 and name == pname):
                        print(f"  Answered a request for {pname} from system {msg.get_srcSystem()}")
                        conn.mav.param_value_send(pname.encode("ascii"), value, MAV.MAV_PARAM_TYPE_INT32,
                                                  len(params), index)
                        break
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
