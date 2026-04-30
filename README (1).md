# Mini IDS

A small C++ intrusion detection system (IDS) prototype that scans a log file for suspicious activity and reports alerts.

## Project Overview

`Mini_IDS` reads log entries from `logs.txt`, checks each entry for:
- repeated failed login attempts by IP address
- SQL injection patterns
- dangerous command strings

It uses a Trie data structure to efficiently match suspicious text patterns within logs.

## Features

- Detects brute force login attacks when an IP has 3 or more `Failed login` entries
- Detects malicious patterns such as:
  - `' OR '1'='1`
  - `DROP TABLE`
  - `UNION SELECT`
  - `sudo rm -rf`
  - `shutdown`
  - `wget malicious`
- Prints alert messages to the console when suspicious activity is found

## Files

- `main.cpp` - main source code implementing the IDS logic
- `logs.txt` - sample log file input
- `README.md` - this project description

## Build Instructions

Use a C++ compiler such as `g++` or Microsoft Visual C++.

Example with `g++`:

```bash
cd "c:\Users\prasa\Downloads\Coding Skills Project\Mini_IDS"
g++ main.cpp -o Mini_IDS.exe
```

## Run Instructions

Ensure `logs.txt` is present in the same folder as the executable, then run:

```bash
Mini_IDS.exe
```

The program will process each log line and print alerts for suspicious activity.

## Log Format

The IDS expects log lines containing an `IP=` field. Example:

```text
2026-04-30 12:00:00 IP=192.168.1.10 User=admin Failed login
```

If a line has no `IP=` field, the program reports the source IP as `Unknown`.

## Notes

- This is a simple educational prototype, not a production IDS.
- The suspicious pattern list is hard-coded in `main.cpp`.
- You can extend the logic by adding more patterns or thresholds.
