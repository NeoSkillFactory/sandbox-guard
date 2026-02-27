# Sandbox Guardian - Usage Guide

## Installation

```bash
cd skill/
npm install
```

## Quick Start

### Scan a file for sandbox escape patterns

```bash
node scripts/detector.js --target path/to/file.js
```

### Scan a directory

```bash
node scripts/detector.js --target path/to/directory/
```

### Run with custom configuration

```bash
node scripts/detector.js --target path/to/file.js --config assets/config.yaml
```

### Process detected threats

```bash
# Save detection results to a file
node scripts/detector.js --target path/to/file.js --output threats.json

# Run mitigation
node scripts/mitigator.js --events threats.json
```

## Example Output

```json
{
  "summary": {
    "filesScanned": 5,
    "threatsFound": 2,
    "highSeverity": 1,
    "mediumSeverity": 1,
    "lowSeverity": 0
  },
  "threats": [
    {
      "id": "proc-access",
      "severity": "high",
      "file": "exploit.js",
      "line": 12,
      "match": "fs.readFileSync('/proc/self/maps')",
      "description": "Access to /proc filesystem which can leak process info or enable escapes",
      "action": "terminateProcess"
    }
  ]
}
```

## Configuration

Edit `assets/config.yaml` to adjust:

- **Detection sensitivity**: `low`, `medium`, or `high`
- **File extensions** to scan
- **Alert severity levels** and their corresponding actions
- **Logging** format and output

## Programmatic Usage

```javascript
const { Detector } = require('./scripts/detector');
const { Mitigator } = require('./scripts/mitigator');

// Initialize
const detector = new Detector();
const mitigator = new Mitigator();

// Scan
const results = detector.scanFile('path/to/suspicious.js');

// Handle threats
if (results.threats.length > 0) {
  const actions = mitigator.process(results.threats);
  console.log('Actions taken:', actions);
}
```
