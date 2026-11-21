# Link Check

**Will your drone obey MAVLink commands from anyone?** Link Check answers that in about 10 seconds.

In March 2026, CISA published [CVE-2026-1579](https://nvd.nist.gov/vuln/detail/CVE-2026-1579), rated critical: unless MAVLink 2 *message signing* is turned on, anyone who can reach a PX4 drone's radio or network link can send it commands. ArduPilot works the same way. The fix is free: turn signing on. Link Check tells you whether you have.

> **Only test drones you own or have written permission to test.**
> Link Check is read-only. It sends one harmless request (it asks to read the drone's first setting) and never arms, moves, reboots, uploads missions or changes a setting.

## What it does

1. Connects to your drone or simulator and waits for its heartbeat.
2. **Check 1:** listens for a few seconds. Are the drone's own messages signed?
3. **Check 2:** sends one unsigned, read-only request for setting number 0. Does the drone answer?

It asks by number, not by name, because names change between firmware versions (current ArduPilot renamed `SYSID_THISMAV` to `MAV_SYSID`).

| Result | Meaning |
| --- | --- |
| **EXPOSED** | The drone answered an unsigned message. Anyone on the link can command it. Link Check prints how to fix it. |
| **PROTECTED** | The drone ignored the unsigned message and signs its own. Signing is on. |
| **UNCLEAR** | No answer, but no signing either. The link may be one-way or lossy. Check it and run again. |

## Install

You need Python 3.9 or newer.

```bash
pip3 install -r requirements.txt
```

On an older Intel Mac, install Python with the installer from python.org rather than Homebrew.

## Try it in 1 minute, no drone needed

`fake_drone.py` is a pretend drone that behaves like a real one. Open two terminal windows in this folder.

**Signing off.** In window 1:

```bash
python3 fake_drone.py
```

In window 2:

```bash
python3 link_check.py
```

You should see **EXPOSED**. Press Ctrl+C in window 1.

**Signing on.** In window 1:

```bash
python3 fake_drone.py --signing "a long passphrase"
```

Run `python3 link_check.py` again in window 2. You should see **PROTECTED**.

## Test the real ArduPilot simulator

Start ArduPilot's simulator (SITL), for example in an Ubuntu virtual machine:

```bash
Tools/autotest/sim_vehicle.py -v ArduCopter
```

Then point Link Check at port **5762**. Port 5760 is the simulator's "USB" port, and ArduPilot skips signing checks on USB, so always test 5762:

```bash
python3 link_check.py --connect tcp:VM_ADDRESS:5762
```

You should see **EXPOSED**. Now turn signing on by typing this in the MAVProxy window:

```
signing setup a long passphrase
```

Run Link Check again: **PROTECTED**.

The simulator saves the key, so signing stays on after a restart. To switch it off again, type `signing remove a long passphrase` in MAVProxy, or restart the simulator with `-w` to wipe its saved settings.

Tested against ArduPilot SITL (Copter, November 2026 code): EXPOSED with signing off, PROTECTED after `signing setup`.

## Real drones

Test over the link an attacker would use, such as your telemetry radio or Wi-Fi, not USB.

```bash
python3 link_check.py --connect udpin:0.0.0.0:14550                 # telemetry over UDP
python3 link_check.py --connect /dev/tty.usbserial-0001 --baud 57600  # telemetry radio
```

Close your ground station first if it already holds the radio's port.

## Options

| Option | Default | What it does |
| --- | --- | --- |
| `--connect` | `tcp:127.0.0.1:5762` | Where the drone is |
| `--baud` | none | Baud rate for serial ports |
| `--timeout` | 10 | Seconds to wait for a heartbeat |
| `--listen` | 5 | Seconds to watch for signed messages |
| `--wait` | 3 | Seconds to wait for an answer |
| `--tries` | 2 | Times to send the read-only request if there's no answer |
| `--json` | off | Print the report as JSON |
| `--yes` | off | Skip the permission question |

Exit codes: `0` PROTECTED, `2` EXPOSED, `3` UNCLEAR, `1` could not run. Handy in scripts.

## Example output

```
Link Check report
  Connection   tcp:127.0.0.1:5762
  Vehicle      Quadrotor, ArduPilot, system 1
  Check 1      Messages from the drone: NOT SIGNED (0 signed, 8 unsigned, 0 MAVLink 1)
  Check 2      Unsigned read of parameter #0: ANSWERED (FORMAT_VERSION = 120)

  EXPOSED  The drone answered an unsigned message. Anyone who can reach this link can send it commands.

  How to fix it
    1. Connect over USB or another link you trust.
    2. Mission Planner: SETUP > Advanced > MAVLink Signing, then add a key.
    3. Or in MAVProxy, type:  signing setup <a long passphrase>
    4. Give the same key to every ground station that flies this drone.
    5. Guide: https://ardupilot.org/copter/docs/common-MAVLink2-signing.html
```

```
Link Check report
  Connection   tcp:127.0.0.1:5762
  Vehicle      Quadrotor, ArduPilot, system 1
  Check 1      Messages from the drone: SIGNED (14 signed, 0 unsigned, 0 MAVLink 1)
  Check 2      Unsigned read of parameter #0: NO ANSWER

  PROTECTED  The drone ignored an unsigned message and signs its own. Message signing is on.
```

## What it doesn't check

- Signing proves who sent a message. It doesn't hide what's in it: anyone can still read your telemetry.
- It doesn't test your ground station, your radio's own settings, or other weaknesses.
- A PROTECTED result is only as good as your key. Use a long passphrase and keep it private.

## License

MIT. See `LICENSE`.
