const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { Mitigator } = require("./mitigator");

describe("Mitigator", () => {
  it("should initialize with default config", () => {
    const mitigator = new Mitigator();
    assert.ok(mitigator.config);
    assert.deepEqual(mitigator.log, []);
  });

  it("should process high severity threats as terminate", () => {
    const mitigator = new Mitigator();
    const threats = [
      {
        id: "proc-access",
        type: "fileAccess",
        severity: "high",
        file: "exploit.js",
        line: 5,
        match: "/proc/self/maps",
        description: "Access to /proc filesystem",
        action: "terminateProcess",
      },
    ];

    const result = mitigator.process(threats);
    assert.equal(result.processed, 1);
    assert.equal(result.actions[0].action, "terminateProcess");
    assert.equal(result.actions[0].status, "flagged");
    assert.equal(result.summary.terminated, 1);
    assert.equal(result.summary.overallStatus, "critical");
  });

  it("should process medium severity threats as block", () => {
    const mitigator = new Mitigator();
    const threats = [
      {
        id: "curl-wget",
        type: "exec",
        severity: "medium",
        file: "download.sh",
        line: 3,
        match: "curl ",
        description: "Network download tool",
        action: "blockAccess",
      },
    ];

    const result = mitigator.process(threats);
    assert.equal(result.actions[0].action, "blockAccess");
    assert.equal(result.actions[0].status, "blocked");
    assert.equal(result.summary.blocked, 1);
    assert.equal(result.summary.overallStatus, "restricted");
  });

  it("should process low severity threats as logAndWatch", () => {
    const mitigator = new Mitigator();
    const threats = [
      {
        id: "test-low",
        type: "test",
        severity: "low",
        file: "test.js",
        line: 1,
        match: "something",
        description: "Low severity test",
        action: "logAndWatch",
      },
    ];

    const result = mitigator.process(threats);
    assert.equal(result.actions[0].action, "logAndWatch");
    assert.equal(result.actions[0].status, "logged");
    assert.equal(result.summary.logged, 1);
    assert.equal(result.summary.overallStatus, "monitored");
  });

  it("should process multiple threats", () => {
    const mitigator = new Mitigator();
    const threats = [
      { id: "t1", severity: "high", file: "a.js", line: 1, match: "x", description: "d1", action: "terminateProcess" },
      { id: "t2", severity: "medium", file: "b.js", line: 2, match: "y", description: "d2", action: "blockAccess" },
      { id: "t3", severity: "low", file: "c.js", line: 3, match: "z", description: "d3", action: "logAndWatch" },
    ];

    const result = mitigator.process(threats);
    assert.equal(result.processed, 3);
    assert.equal(result.summary.terminated, 1);
    assert.equal(result.summary.blocked, 1);
    assert.equal(result.summary.logged, 1);
    assert.equal(result.summary.overallStatus, "critical");
  });

  it("should return clean status for no threats", () => {
    const mitigator = new Mitigator();
    const result = mitigator.process([]);
    assert.equal(result.processed, 0);
    assert.equal(result.summary.overallStatus, "clean");
  });

  it("should maintain log of events", () => {
    const mitigator = new Mitigator();
    mitigator.process([
      { id: "t1", severity: "low", file: "a.js", line: 1, match: "x", description: "d1", action: "logAndWatch" },
    ]);
    mitigator.process([
      { id: "t2", severity: "low", file: "b.js", line: 2, match: "y", description: "d2", action: "logAndWatch" },
    ]);

    const log = mitigator.getLog();
    assert.equal(log.length, 2);
  });

  it("should generate text report", () => {
    const mitigator = new Mitigator();
    mitigator.process([
      { id: "t1", severity: "high", file: "a.js", line: 1, match: "x", description: "d1", action: "terminateProcess" },
    ]);
    const report = mitigator.generateReport();
    assert.ok(report.includes("Sandbox Guardian"));
    assert.ok(report.includes("CRITICAL"));
    assert.ok(report.includes("terminateProcess"));
  });

  it("should handle threats with default action from severity", () => {
    const mitigator = new Mitigator();
    const threats = [
      { id: "t1", severity: "high", file: "a.js", line: 1, match: "x", description: "d1" },
    ];
    const result = mitigator.process(threats);
    assert.equal(result.actions[0].action, "terminateProcess");
  });
});
