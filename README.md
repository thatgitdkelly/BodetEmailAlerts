# Bodet System UDP Listener & Monitor

A lightweight Python-based UDP listener and event processor for monitoring a Bodet bell system. Originally developed through reverse engineering, this tool detects melody, button, and system check-in events, logging them and triggering optional email alerts.

## Features

- Listens for Bodet UDP broadcast packets
- Detects:
  - Melody events (e.g. school bell sequences)
  - Button presses (e.g. Lockdown, All Clear, Stop)
  - Device check-ins
- Sends email alerts for specific button or melody events
- Logs all events to file and system journal
- Auto-starts on boot via systemd service
- Fully standalone—uses Python standard libraries only

## Packet Analysis

The listener identifies packet types using hex-based matching for common Bodet headers:

| Packet Type     | Header   | Description           |
|------------------|----------|------------------------|
| Melody           | `4d454c` | Melody playback event  |
| Button Press     | `424f55` | Physical button event  |
| Check-in (REL)   | `52454c` | Regular status update  |

Further analysis was performed using `tcpdump` and `Wireshark` to isolate event types and deduce byte structure.

## Systemd Integration

The script is managed as a systemd service:

```bash
sudo systemctl enable bodet-listener.service
sudo systemctl start bodet-listener.service
sudo systemctl status bodet-listener.service
