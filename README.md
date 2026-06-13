# Compliance Check — Rule-Based Compliance Evaluation Framework

**A compliance checker** is a pluggable framework that evaluates a set of rules against a configuration context and produces structured pass/fail results. Each rule is self-contained, independently testable, and reports its severity level — enabling automated policy enforcement for security baselines, regulatory requirements, and operational standards.

## Why It Matters

Every organization that touches regulated data (HIPAA, SOC 2, PCI-DSS, GDPR) needs automated compliance checking. Manually auditing infrastructure for 200+ controls is error-prone and expensive. This framework lets you encode each control as a `ComplianceRule` — a trait object with an `id`, `description`, and `check()` method. Run them all against a key-value context and get a structured report: which rules passed, which failed (with explanations), and their severity. This is the same pattern used by AWS Config Rules, Open Policy Agent (OPA), Chef InSpec, and HashiCorp Sentinel — just far simpler and library-embedded.

## How It Works

### Rule Model

Each rule implements the `ComplianceRule` trait:

```rust
pub trait ComplianceRule: Send + Sync {
    fn id(&self) -> &str;
    fn description(&self) -> &str;
    fn check(&self, context: &HashMap<String, String>) -> CheckResult;
}
```

The `check()` method receives a context map — typically populated from infrastructure state, environment variables, or configuration files. It returns one of:

| Status | Meaning |
|---|---|
| `Pass` | The control is satisfied. |
| `Fail(reason)` | The control is violated, with an explanation. |
| `NotApplicable` | The rule doesn't apply to this context. |
| `ManualReview` | The rule requires human verification. |

### Severity Levels

Each `CheckResult` carries a severity:

`Critical > High > Medium > Low > Info`

This enables priority-ordered reporting: fix all `Critical` failures before looking at `Low` ones.

### Evaluation

The checker runs all registered rules sequentially against the context:

```
results = rules.map(|r| r.check(context))
```

**Complexity**: `O(R × C)` where `R` = number of rules and `C` = average cost of a single rule's check function (typically `O(1)` — a hashmap lookup or string comparison).

## Quick Start

```rust
use compliance_check::{
    ComplianceChecker, ComplianceRule, CheckResult,
    ComplianceStatus, Severity,
};
use std::collections::HashMap;

struct EncryptionRule;
impl ComplianceRule for EncryptionRule {
    fn id(&self) -> &str { "ENC-001" }
    fn description(&self) -> &str { "Data disks must be encrypted" }
    fn check(&self, ctx: &HashMap<String, String>) -> CheckResult {
        match ctx.get("disk_encrypted") {
            Some(v) if v == "true" => CheckResult {
                rule_id: self.id().into(),
                description: self.description().into(),
                status: ComplianceStatus::Pass,
                severity: Severity::Critical,
            },
            _ => CheckResult {
                rule_id: self.id().into(),
                description: self.description().into(),
                status: ComplianceStatus::Fail("Disk encryption not enabled".into()),
                severity: Severity::Critical,
            },
        }
    }
}

let mut checker = ComplianceChecker::new();
checker.add_rule(Box::new(EncryptionRule));

let mut ctx = HashMap::new();
ctx.insert("disk_encrypted".into(), "true".into());

let results = checker.run_all(&ctx);
assert_eq!(results[0].status, ComplianceStatus::Pass);
```

## API

| Type / Method | Description |
|---|---|
| `ComplianceChecker` | Registry of rules. Add with `add_rule()`, run with `run_all()`. |
| `ComplianceRule` (trait) | Implement this: `id()`, `description()`, `check(context)`. |
| `CheckResult` | `{ rule_id, description, status, severity }`. |
| `ComplianceStatus` | `Pass`, `Fail(String)`, `NotApplicable`, `ManualReview`. |
| `Severity` | `Critical`, `High`, `Medium`, `Low`, `Info`. |

## Architecture Notes

Compliance checking serves the η (evaluation) side of γ + η = C in SuperInstance. It encodes policy as code, automatically verifying that fleet configurations meet security and operational baselines before deployment and continuously thereafter. See [SuperInstance Architecture](https://github.com/SuperInstance/SuperInstance/blob/main/ARCHITECTURE.md).

## References

1. NIST Special Publication 800-53 Rev. 5. *Security and Privacy Controls for Information Systems and Organizations*. — Standard control catalog.
2. CIS Benchmarks. <https://www.cisecurity.org/cis-benchmarks> — Industry-standard compliance rules.
3. Papa, M. (2020). *Security as Code*. O'Reilly. — Encoding compliance as executable rules.

## License

MIT
