---
name: sandbox-guard
description: Automatically detects and mitigates sandbox escape attempts to prevent OpenClaw from bypassing security boundaries.
version: 1.0.0
triggers:
  - "check for sandbox escape"
  - "scan for security boundary violations"
  - "detect sandbox bypass"
  - "review code for sandbox escape"
  - "monitor agent for suspicious access"
---

# Sandbox Guardian

## Purpose
Automated security mechanism to prevent sandbox escape attempts in OpenClaw.

## Core Capabilities

1. **Monitoring** - Tracks system call patterns and file access for suspicious activity
2. **Detection** - Identifies bypass attempts using regex patterns and behavioral analysis
3. **Mitigation** - Implements containment via process termination, access blocking, or isolation
4. **Logging** - Records all security events with timestamps and context
5. **Integration** - Exposes CLI and programmatic API for agent workflow triggers

## Usage

### CLI
```bash
# Scan a script or file for sandbox escape patterns
node scripts/detector.js --target <file-or-directory>

# Run with custom rules
node scripts/detector.js --target <file> --rules scripts/rules.json

# Run mitigation on detected threats
node scripts/mitigator.js --events <events.json>
```

### Programmatic
```javascript
const { Detector } = require('./scripts/detector');
const { Mitigator } = require('./scripts/mitigator');

const detector = new Detector();
const results = detector.scanFile('/path/to/file.js');

if (results.threats.length > 0) {
  const mitigator = new Mitigator();
  mitigator.process(results.threats);
}
```

## Security Rules

- **File access restrictions** - Detects writes to /proc, /dev, /sys, and other sensitive paths
- **Process execution limits** - Flags absolute path script execution and shell spawning
- **Network restrictions** - Identifies unauthorized socket creation
- **Symlink attacks** - Detects symlink creation targeting restricted paths
- **Environment manipulation** - Flags attempts to modify PATH or LD_PRELOAD

## Configuration

See `assets/config.yaml` for:
- Detection threshold sensitivity settings
- Alert severity levels
- Integration hooks for OpenClaw agents
