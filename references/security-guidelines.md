# Sandbox Security Guidelines

## Overview

This document outlines the security boundaries enforced by Sandbox Guardian and the principles behind its detection rules.

## Sandbox Boundaries

### File System Restrictions

The sandbox restricts access to sensitive filesystem paths:

| Path | Risk | Rationale |
|------|------|-----------|
| `/proc/*` | High | Process information leakage, namespace escape |
| `/sys/*` | High | Kernel parameter modification |
| `/dev/tty*` | High | Terminal injection attacks |
| `/etc/passwd` | High | User enumeration |
| `/etc/shadow` | High | Password hash access |
| `~/.ssh/*` | High | SSH key theft |

### Process Execution Restrictions

- **Shell spawning**: Direct shell invocation (`bash`, `sh`, `zsh`) is flagged as it provides unrestricted command execution
- **Child processes**: `child_process` module usage is monitored as it can bypass Node.js sandbox
- **Dynamic evaluation**: `eval()`, `Function()`, and `vm.runIn*` are flagged for arbitrary code execution

### Network Restrictions

- Raw socket creation requires explicit approval
- Download tools (`curl`, `wget`) are flagged for potential payload fetching
- WebSocket connections are monitored for data exfiltration

### Environment Manipulation

- `PATH` modification can redirect command execution
- `LD_PRELOAD` injection can intercept system calls
- `LD_LIBRARY_PATH` changes can load malicious shared libraries

## Detection Methodology

### Static Analysis

The detector scans source code files for patterns matching known escape techniques:

1. **Regex matching** against a ruleset defined in `rules.json`
2. **Context-aware analysis** that considers surrounding code
3. **Severity classification** based on potential impact

### Response Strategies

| Severity | Response | Description |
|----------|----------|-------------|
| High | Terminate | Immediately flag for process termination |
| Medium | Block | Restrict access to the targeted resource |
| Low | Log & Watch | Record the event for further analysis |

## Best Practices

1. **Principle of Least Privilege**: Only grant the minimum permissions needed
2. **Defense in Depth**: Layer multiple detection mechanisms
3. **Fail Secure**: Default to denying access when uncertain
4. **Audit Trail**: Log all security-relevant events for review
5. **Regular Updates**: Keep detection rules current with new escape techniques
