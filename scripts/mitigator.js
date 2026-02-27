#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const yaml = require("js-yaml");

const DEFAULT_CONFIG_PATH = path.join(__dirname, "..", "assets", "config.yaml");

class Mitigator {
  constructor(options = {}) {
    this.configPath = options.configPath || DEFAULT_CONFIG_PATH;
    this.config = this._loadConfig();
    this.log = [];
  }

  _loadConfig() {
    try {
      const raw = fs.readFileSync(this.configPath, "utf8");
      return yaml.load(raw);
    } catch {
      return {
        alerts: {
          severity_levels: {
            high: { action: "terminateProcess", notify: true, log_level: "error" },
            medium: { action: "blockAccess", notify: true, log_level: "warn" },
            low: { action: "logAndWatch", notify: false, log_level: "info" },
          },
        },
        logging: { enabled: true, format: "json" },
      };
    }
  }

  process(threats) {
    const results = [];

    for (const threat of threats) {
      const result = this._mitigate(threat);
      results.push(result);
      this._logEvent(result);
    }

    return {
      processed: results.length,
      actions: results,
      summary: this._summarizeActions(results),
    };
  }

  _mitigate(threat) {
    const timestamp = new Date().toISOString();
    const action = threat.action || this._getAction(threat.severity);

    switch (action) {
      case "terminateProcess":
        return this._handleTerminate(threat, timestamp);
      case "blockAccess":
        return this._handleBlock(threat, timestamp);
      case "logAndWatch":
        return this._handleLogAndWatch(threat, timestamp);
      default:
        return this._handleLogAndWatch(threat, timestamp);
    }
  }

  _getAction(severity) {
    const levels = this.config.alerts?.severity_levels || {};
    const level = levels[severity];
    return level ? level.action : "logAndWatch";
  }

  _handleTerminate(threat, timestamp) {
    return {
      threatId: threat.id,
      severity: threat.severity,
      action: "terminateProcess",
      status: "flagged",
      timestamp,
      file: threat.file,
      line: threat.line,
      message: `CRITICAL: Process termination recommended for threat "${threat.id}" at ${threat.file}:${threat.line}. Match: "${threat.match}". ${threat.description}`,
      recommendation: "Review the flagged code and remove or sandbox the dangerous operation.",
    };
  }

  _handleBlock(threat, timestamp) {
    return {
      threatId: threat.id,
      severity: threat.severity,
      action: "blockAccess",
      status: "blocked",
      timestamp,
      file: threat.file,
      line: threat.line,
      message: `WARNING: Access blocked for threat "${threat.id}" at ${threat.file}:${threat.line}. Match: "${threat.match}". ${threat.description}`,
      recommendation: "Ensure the operation uses approved APIs instead of direct system access.",
    };
  }

  _handleLogAndWatch(threat, timestamp) {
    return {
      threatId: threat.id,
      severity: threat.severity,
      action: "logAndWatch",
      status: "logged",
      timestamp,
      file: threat.file,
      line: threat.line,
      message: `NOTICE: Event logged for threat "${threat.id}" at ${threat.file}:${threat.line}. Match: "${threat.match}". ${threat.description}`,
      recommendation: "Monitor for repeated occurrences; escalate if pattern persists.",
    };
  }

  _logEvent(result) {
    this.log.push(result);

    const shouldNotify = this.config.alerts?.severity_levels?.[result.severity]?.notify;
    if (shouldNotify) {
      const logLevel = this.config.alerts?.severity_levels?.[result.severity]?.log_level || "info";
      const logFn = logLevel === "error" ? console.error : logLevel === "warn" ? console.warn : console.log;
      logFn(`[sandbox-guard] [${logLevel.toUpperCase()}] ${result.message}`);
    }
  }

  _summarizeActions(results) {
    const terminated = results.filter((r) => r.action === "terminateProcess").length;
    const blocked = results.filter((r) => r.action === "blockAccess").length;
    const logged = results.filter((r) => r.action === "logAndWatch").length;

    let overallStatus = "clean";
    if (terminated > 0) overallStatus = "critical";
    else if (blocked > 0) overallStatus = "restricted";
    else if (logged > 0) overallStatus = "monitored";

    return {
      totalActions: results.length,
      terminated,
      blocked,
      logged,
      overallStatus,
    };
  }

  getLog() {
    return [...this.log];
  }

  generateReport() {
    const actions = this.log;
    const summary = this._summarizeActions(actions);

    const lines = [];
    lines.push("=== Sandbox Guardian - Mitigation Report ===");
    lines.push("");
    lines.push(`Overall Status: ${summary.overallStatus.toUpperCase()}`);
    lines.push(`Total Actions: ${summary.totalActions}`);
    lines.push(`  Terminated: ${summary.terminated}  Blocked: ${summary.blocked}  Logged: ${summary.logged}`);
    lines.push("");

    for (const a of actions) {
      lines.push(`[${a.severity.toUpperCase()}] ${a.threatId} - ${a.action} (${a.status})`);
      lines.push(`  File: ${a.file}:${a.line}`);
      lines.push(`  ${a.message}`);
      lines.push(`  Recommendation: ${a.recommendation}`);
      lines.push("");
    }

    return lines.join("\n");
  }
}

function parseArgs(argv) {
  const args = { events: null, config: null, output: null, format: "json" };
  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case "--events":
        args.events = argv[++i];
        break;
      case "--config":
        args.config = argv[++i];
        break;
      case "--output":
        args.output = argv[++i];
        break;
      case "--format":
        args.format = argv[++i];
        break;
      case "--help":
        console.log(`sandbox-guard mitigator

Usage:
  node mitigator.js --events <events.json> [options]

Options:
  --events <path>    Path to JSON file containing detected threats (required)
  --config <path>    Path to config.yaml (default: assets/config.yaml)
  --output <path>    Write results to file instead of stdout
  --format <type>    Output format: json (default) or text
  --help             Show this help message`);
        process.exit(0);
    }
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv);

  if (!args.events) {
    console.log(JSON.stringify({
      status: "idle",
      message: "No events file specified. Use --events <path> to process detected threats. Use --help for more options.",
    }, null, 2));
    process.exit(0);
  }

  const options = {};
  if (args.config) options.configPath = path.resolve(args.config);

  const mitigator = new Mitigator(options);

  let threats;
  try {
    const raw = fs.readFileSync(path.resolve(args.events), "utf8");
    const data = JSON.parse(raw);
    threats = data.threats || data;
    if (!Array.isArray(threats)) {
      console.error(JSON.stringify({ error: "Events file must contain a 'threats' array or be an array of threats." }));
      process.exit(1);
    }
  } catch (err) {
    console.error(JSON.stringify({ error: `Cannot read events file: ${err.message}` }));
    process.exit(1);
  }

  const result = mitigator.process(threats);

  let output;
  if (args.format === "text") {
    output = mitigator.generateReport();
  } else {
    output = JSON.stringify(result, null, 2);
  }

  if (args.output) {
    fs.writeFileSync(args.output, output, "utf8");
    console.log(`Mitigation report written to ${args.output}`);
  } else {
    console.log(output);
  }

  if (result.summary.overallStatus === "critical") {
    process.exit(2);
  }
}

if (require.main === module) {
  main();
}

module.exports = { Mitigator };
