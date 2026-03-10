const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { Detector } = require("./detector");

const TMP_DIR = path.join(__dirname, "..", ".test-tmp");

function setup() {
  fs.mkdirSync(TMP_DIR, { recursive: true });
}

function teardown() {
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
}

function writeTmpFile(name, content) {
  const p = path.join(TMP_DIR, name);
  fs.writeFileSync(p, content, "utf8");
  return p;
}

describe("Detector", () => {
  beforeEach(() => setup());
  afterEach(() => teardown());

  it("should load rules and config without error", () => {
    const detector = new Detector();
    assert.ok(detector.rules);
    assert.ok(detector.rules.patterns.length > 0);
    assert.ok(detector.config);
  });

  it("should detect /proc access in a file", () => {
    const filePath = writeTmpFile("test1.js", `
const fs = require('fs');
const maps = fs.readFileSync('/proc/self/maps');
console.log(maps);
`);
    const detector = new Detector();
    const result = detector.scanFile(filePath);
    assert.ok(result.threats.length > 0);
    const procThreat = result.threats.find((t) => t.id === "proc-access");
    assert.ok(procThreat, "Should detect /proc access");
    assert.equal(procThreat.severity, "high");
  });

  it("should detect shell spawning", () => {
    const filePath = writeTmpFile("test2.js", `
const { exec } = require('child_process');
exec('bash -c "whoami"');
`);
    const detector = new Detector();
    const result = detector.scanFile(filePath);
    const shellThreat = result.threats.find((t) => t.id === "shell-spawn");
    assert.ok(shellThreat, "Should detect shell spawning");
    const cpThreat = result.threats.find((t) => t.id === "child-process");
    assert.ok(cpThreat, "Should detect child_process usage");
  });

  it("should detect environment variable manipulation", () => {
    const filePath = writeTmpFile("test3.sh", `#!/bin/bash
PATH=/tmp/evil:$PATH
LD_PRELOAD=/tmp/evil.so ./target
`);
    const detector = new Detector();
    const result = detector.scanFile(filePath);
    const envThreat = result.threats.find((t) => t.id === "env-manipulation");
    assert.ok(envThreat, "Should detect env manipulation");
    assert.equal(envThreat.severity, "high");
  });

  it("should detect eval usage", () => {
    const filePath = writeTmpFile("test4.js", `
const code = "process.exit(1)";
eval(code);
`);
    const detector = new Detector();
    const result = detector.scanFile(filePath);
    const evalThreat = result.threats.find((t) => t.id === "eval-usage");
    assert.ok(evalThreat, "Should detect eval usage");
  });

  it("should detect network socket creation", () => {
    const filePath = writeTmpFile("test5.js", `
const net = require('net');
const client = net.connect({ port: 4444, host: '10.0.0.1' });
`);
    const detector = new Detector();
    const result = detector.scanFile(filePath);
    const netThreat = result.threats.find((t) => t.id === "socket-create");
    assert.ok(netThreat, "Should detect socket creation");
  });

  it("should detect sensitive file access", () => {
    const filePath = writeTmpFile("test6.js", `
const fs = require('fs');
const passwd = fs.readFileSync('/etc/passwd', 'utf8');
`);
    const detector = new Detector();
    const result = detector.scanFile(filePath);
    const sensThreat = result.threats.find((t) => t.id === "fs-sensitive-paths");
    assert.ok(sensThreat, "Should detect /etc/passwd access");
  });

  it("should return no threats for safe code", () => {
    const filePath = writeTmpFile("safe.js", `
const x = 1 + 2;
console.log("Hello, world!", x);

function add(a, b) {
  return a + b;
}

module.exports = { add };
`);
    const detector = new Detector();
    const result = detector.scanFile(filePath);
    assert.equal(result.threats.length, 0, "Safe code should have no threats");
  });

  it("should scan directories", () => {
    writeTmpFile("a.js", 'eval("hello");\n');
    writeTmpFile("b.js", "const x = 1;\n");
    const detector = new Detector();
    const result = detector.scanDirectory(TMP_DIR);
    assert.ok(result.filesScanned >= 2);
    assert.ok(result.summary);
    assert.ok(result.threats.length > 0);
  });

  it("should scan content directly", () => {
    const detector = new Detector();
    const result = detector.scanContent('eval("danger");\nconst net = net.connect({port:80});');
    assert.ok(result.threats.length > 0);
  });

  it("should produce correct summary", () => {
    const detector = new Detector();
    const result = detector.scanContent('fs.readFileSync("/proc/self/maps");\neval("x");');
    assert.ok(result.summary);
    assert.ok(result.summary.totalThreats > 0);
    assert.equal(typeof result.summary.highSeverity, "number");
    assert.equal(typeof result.summary.mediumSeverity, "number");
  });

  it("should check thresholds correctly", () => {
    const detector = new Detector();
    const safe = { highSeverity: 0, mediumSeverity: 0, lowSeverity: 0 };
    assert.ok(detector.checkThresholds(safe).passed);

    const critical = { highSeverity: 5, mediumSeverity: 0, lowSeverity: 0 };
    assert.ok(!detector.checkThresholds(critical).passed);
  });

  it("should handle unreadable files gracefully", () => {
    const detector = new Detector();
    const result = detector.scanFile("/nonexistent/file.js");
    assert.ok(result.error);
    assert.equal(result.threats.length, 0);
  });

  it("should not false-positive on words containing shell names", () => {
    const filePath = writeTmpFile("no-fp.js", `
git push origin main
const crashed = true;
flashcard.show();
`);
    const detector = new Detector();
    const result = detector.scanFile(filePath);
    const shellThreat = result.threats.find((t) => t.id === "shell-spawn");
    assert.equal(shellThreat, undefined, "Should not flag 'push', 'crash', 'flash' as shell spawning");
  });

  it("should still detect standalone shell commands", () => {
    const filePath = writeTmpFile("real-shell.sh", `#!/bin/bash
sh -c "id"
bash -c "whoami"
`);
    const detector = new Detector();
    const result = detector.scanFile(filePath);
    const shellThreats = result.threats.filter((t) => t.id === "shell-spawn");
    assert.ok(shellThreats.length >= 2, "Should detect sh and bash invocations");
  });

  it("should skip node_modules during directory scan", () => {
    const nmDir = path.join(TMP_DIR, "node_modules");
    fs.mkdirSync(nmDir, { recursive: true });
    fs.writeFileSync(path.join(nmDir, "evil.js"), 'eval("hack");', "utf8");
    writeTmpFile("safe.js", "const x = 1;\n");
    const detector = new Detector();
    const result = detector.scanDirectory(TMP_DIR);
    const nmThreats = result.threats.filter((t) => t.file.includes("node_modules"));
    assert.equal(nmThreats.length, 0, "Should not scan node_modules");
  });

  it("should respect file extension filter in directory scan", () => {
    writeTmpFile("data.txt", 'eval("ignored");');
    writeTmpFile("code.js", "const x = 1;\n");
    const detector = new Detector();
    const result = detector.scanDirectory(TMP_DIR);
    const txtThreats = result.threats.filter((t) => t.file.endsWith(".txt"));
    assert.equal(txtThreats.length, 0, "Should not scan .txt files");
  });

  it("should detect multiple threat types in the same file", () => {
    const filePath = writeTmpFile("multi.js", `
const cp = require('child_process');
eval('fs.readFileSync("/proc/self/maps")');
net.connect({port: 4444});
`);
    const detector = new Detector();
    const result = detector.scanFile(filePath);
    const ids = new Set(result.threats.map((t) => t.id));
    assert.ok(ids.has("child-process"), "Should detect child_process");
    assert.ok(ids.has("eval-usage"), "Should detect eval");
    assert.ok(ids.has("proc-access"), "Should detect /proc access");
    assert.ok(ids.has("socket-create"), "Should detect socket creation");
  });
});
