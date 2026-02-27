#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const yaml = require("js-yaml");

const DEFAULT_RULES_PATH = path.join(__dirname, "rules.json");
const DEFAULT_CONFIG_PATH = path.join(__dirname, "..", "assets", "config.yaml");

class Detector {
  constructor(options = {}) {
    this.rulesPath = options.rulesPath || DEFAULT_RULES_PATH;
    this.configPath = options.configPath || DEFAULT_CONFIG_PATH;
    this.rules = this._loadRules();
    this.config = this._loadConfig();
  }

  _loadRules() {
    const raw = fs.readFileSync(this.rulesPath, "utf8");
    return JSON.parse(raw);
  }

  _loadConfig() {
    try {
      const raw = fs.readFileSync(this.configPath, "utf8");
      return yaml.load(raw);
    } catch {
      return {
        detection: { sensitivity: "medium", file_extensions: [".js", ".ts", ".sh", ".py"] },
        logging: { enabled: true, format: "json" },
      };
    }
  }

  scanFile(filePath) {
    const threats = [];
    let content;

    try {
      content = fs.readFileSync(filePath, "utf8");
    } catch (err) {
      return { file: filePath, error: `Cannot read file: ${err.message}`, threats: [] };
    }

    const lines = content.split("\n");

    for (const rule of this.rules.patterns) {
      const regex = new RegExp(rule.match, "g");

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        let m;
        while ((m = regex.exec(line)) !== null) {
          threats.push({
            id: rule.id,
            type: rule.type,
            severity: rule.severity,
            file: filePath,
            line: i + 1,
            column: m.index + 1,
            match: m[0],
            context: line.trim(),
            description: rule.description,
            action: this.rules.actions[rule.severity],
          });
        }
      }
    }

    return { file: filePath, threats };
  }

  scanDirectory(dirPath) {
    const allowedExtensions = this.config.detection?.file_extensions || [".js", ".ts", ".sh", ".py"];
    const maxSizeKB = this.config.detection?.max_file_size_kb || 1024;
    const scanHidden = this.config.detection?.scan_hidden_files || false;

    const allThreats = [];
    const filesScanned = [];
    const errors = [];

    const walk = (dir) => {
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch (err) {
        errors.push({ path: dir, error: err.message });
        return;
      }

      for (const entry of entries) {
        if (!scanHidden && entry.name.startsWith(".")) continue;
        if (entry.name === "node_modules") continue;

        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          walk(fullPath);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name);
          if (!allowedExtensions.includes(ext)) continue;

          try {
            const stats = fs.statSync(fullPath);
            if (stats.size > maxSizeKB * 1024) continue;
          } catch {
            continue;
          }

          const result = this.scanFile(fullPath);
          filesScanned.push(fullPath);
          if (result.error) {
            errors.push({ path: fullPath, error: result.error });
          } else {
            allThreats.push(...result.threats);
          }
        }
      }
    };

    walk(dirPath);

    return {
      directory: dirPath,
      filesScanned: filesScanned.length,
      threats: allThreats,
      errors,
      summary: this._summarize(allThreats),
    };
  }

  scanContent(content, sourceName = "<stdin>") {
    const threats = [];
    const lines = content.split("\n");

    for (const rule of this.rules.patterns) {
      const regex = new RegExp(rule.match, "g");

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        let m;
        while ((m = regex.exec(line)) !== null) {
          threats.push({
            id: rule.id,
            type: rule.type,
            severity: rule.severity,
            file: sourceName,
            line: i + 1,
            column: m.index + 1,
            match: m[0],
            context: line.trim(),
            description: rule.description,
            action: this.rules.actions[rule.severity],
          });
        }
      }
    }

    return { file: sourceName, threats, summary: this._summarize(threats) };
  }

  _summarize(threats) {
    const high = threats.filter((t) => t.severity === "high").length;
    const medium = threats.filter((t) => t.severity === "medium").length;
    const low = threats.filter((t) => t.severity === "low").length;

    const thresholds = this.rules.thresholds || { maxHighSeverity: 0, maxMediumSeverity: 3, maxLowSeverity: 10 };

    let status = "safe";
    if (high > thresholds.maxHighSeverity) status = "critical";
    else if (medium > thresholds.maxMediumSeverity) status = "warning";
    else if (low > thresholds.maxLowSeverity) status = "notice";
    else if (high + medium + low > 0) status = "warning";

    return {
      totalThreats: threats.length,
      highSeverity: high,
      mediumSeverity: medium,
      lowSeverity: low,
      status,
    };
  }

  checkThresholds(summary) {
    const thresholds = this.rules.thresholds || { maxHighSeverity: 0, maxMediumSeverity: 3, maxLowSeverity: 10 };
    const violations = [];

    if (summary.highSeverity > thresholds.maxHighSeverity) {
      violations.push(`High severity threats (${summary.highSeverity}) exceed threshold (${thresholds.maxHighSeverity})`);
    }
    if (summary.mediumSeverity > thresholds.maxMediumSeverity) {
      violations.push(`Medium severity threats (${summary.mediumSeverity}) exceed threshold (${thresholds.maxMediumSeverity})`);
    }
    if (summary.lowSeverity > thresholds.maxLowSeverity) {
      violations.push(`Low severity threats (${summary.lowSeverity}) exceed threshold (${thresholds.maxLowSeverity})`);
    }

    return { passed: violations.length === 0, violations };
  }
}

function parseArgs(argv) {
  const args = { target: null, config: null, rules: null, output: null, format: "json" };
  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case "--target":
        args.target = argv[++i];
        break;
      case "--config":
        args.config = argv[++i];
        break;
      case "--rules":
        args.rules = argv[++i];
        break;
      case "--output":
        args.output = argv[++i];
        break;
      case "--format":
        args.format = argv[++i];
        break;
      case "--help":
        console.log(`sandbox-guard detector

Usage:
  node detector.js --target <file-or-directory> [options]

Options:
  --target <path>    File or directory to scan (required)
  --config <path>    Path to config.yaml (default: assets/config.yaml)
  --rules <path>     Path to rules.json (default: scripts/rules.json)
  --output <path>    Write results to file instead of stdout
  --format <type>    Output format: json (default) or text
  --help             Show this help message`);
        process.exit(0);
    }
  }
  return args;
}

function formatText(result) {
  const lines = [];
  const summary = result.summary || { totalThreats: 0, highSeverity: 0, mediumSeverity: 0, lowSeverity: 0, status: "safe" };

  lines.push("=== Sandbox Guardian - Detection Report ===");
  lines.push("");

  if (result.directory) {
    lines.push(`Directory: ${result.directory}`);
    lines.push(`Files scanned: ${result.filesScanned}`);
  } else {
    lines.push(`File: ${result.file}`);
  }

  lines.push(`Status: ${summary.status.toUpperCase()}`);
  lines.push(`Total threats: ${summary.totalThreats}`);
  lines.push(`  High: ${summary.highSeverity}  Medium: ${summary.mediumSeverity}  Low: ${summary.lowSeverity}`);
  lines.push("");

  const threats = result.threats || [];
  if (threats.length === 0) {
    lines.push("No threats detected.");
  } else {
    for (const t of threats) {
      lines.push(`[${t.severity.toUpperCase()}] ${t.id} at ${t.file}:${t.line}:${t.column}`);
      lines.push(`  Match: ${t.match}`);
      lines.push(`  Context: ${t.context}`);
      lines.push(`  Description: ${t.description}`);
      lines.push(`  Action: ${t.action}`);
      lines.push("");
    }
  }

  return lines.join("\n");
}

function main() {
  const args = parseArgs(process.argv);

  if (!args.target) {
    console.log(JSON.stringify({
      status: "safe",
      message: "No target specified. Use --target <path> to scan a file or directory. Use --help for more options.",
      summary: { totalThreats: 0, highSeverity: 0, mediumSeverity: 0, lowSeverity: 0, status: "safe" },
    }, null, 2));
    process.exit(0);
  }

  const options = {};
  if (args.rules) options.rulesPath = path.resolve(args.rules);
  if (args.config) options.configPath = path.resolve(args.config);

  const detector = new Detector(options);
  const targetPath = path.resolve(args.target);

  let result;
  try {
    const stats = fs.statSync(targetPath);
    if (stats.isDirectory()) {
      result = detector.scanDirectory(targetPath);
    } else {
      const fileResult = detector.scanFile(targetPath);
      result = {
        ...fileResult,
        filesScanned: 1,
        summary: detector._summarize(fileResult.threats),
      };
    }
  } catch (err) {
    console.error(JSON.stringify({ error: `Cannot access target: ${err.message}` }));
    process.exit(1);
  }

  const thresholdCheck = detector.checkThresholds(result.summary);
  result.thresholdCheck = thresholdCheck;

  let output;
  if (args.format === "text") {
    output = formatText(result);
  } else {
    output = JSON.stringify(result, null, 2);
  }

  if (args.output) {
    fs.writeFileSync(args.output, output, "utf8");
    console.log(`Results written to ${args.output}`);
  } else {
    console.log(output);
  }

  if (!thresholdCheck.passed) {
    process.exit(2);
  }
}

if (require.main === module) {
  main();
}

module.exports = { Detector };
