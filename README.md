# sandbox-guard

![Audit](https://img.shields.io/badge/audit%3A%20PASS-brightgreen) ![License](https://img.shields.io/badge/license-MIT-blue) ![OpenClaw](https://img.shields.io/badge/OpenClaw-skill-orange)

> Automatically detects and mitigates sandbox escape attempts to prevent OpenClaw from bypassing security boundaries.

## Features

1. **Monitoring** - Tracks system call patterns and file access for suspicious activity
2. **Detection** - Identifies bypass attempts using regex patterns and behavioral analysis
3. **Mitigation** - Implements containment via process termination, access blocking, or isolation
4. **Logging** - Records all security events with timestamps and context
5. **Integration** - Exposes CLI and programmatic API for agent workflow triggers

## Configuration

See `assets/config.yaml` for:
- Detection threshold sensitivity settings
- Alert severity levels
- Integration hooks for OpenClaw agents

## GitHub

Source code: [github.com/NeoSkillFactory/sandbox-guard](https://github.com/NeoSkillFactory/sandbox-guard)

## License

MIT © NeoSkillFactory