use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum ComplianceStatus {
    Pass,
    Fail(String),
    NotApplicable,
    ManualReview,
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub rule_id: String,
    pub description: String,
    pub status: ComplianceStatus,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

pub trait ComplianceRule: Send + Sync {
    fn id(&self) -> &str;
    fn description(&self) -> &str;
    fn check(&self, context: &HashMap<String, String>) -> CheckResult;
}

#[derive(Default)]
pub struct ComplianceChecker {
    rules: Vec<Box<dyn ComplianceRule>>,
}

impl std::fmt::Debug for ComplianceChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComplianceChecker")
            .field("rule_count", &self.rules.len())
            .finish()
    }
}

impl ComplianceChecker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: Box<dyn ComplianceRule>) {
        self.rules.push(rule);
    }

    pub fn run_all(&self, context: &HashMap<String, String>) -> Vec<CheckResult> {
        self.rules.iter().map(|r| r.check(context)).collect()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyRule;
    impl ComplianceRule for DummyRule {
        fn id(&self) -> &str { "DUMMY-001" }
        fn description(&self) -> &str { "Always passes" }
        fn check(&self, _ctx: &HashMap<String, String>) -> CheckResult {
            CheckResult {
                rule_id: self.id().to_string(),
                description: self.description().to_string(),
                status: ComplianceStatus::Pass,
                severity: Severity::Low,
            }
        }
    }

    #[test]
    fn test_dummy_rule() {
        let mut checker = ComplianceChecker::new();
        checker.add_rule(Box::new(DummyRule));
        let results = checker.run_all(&HashMap::new());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ComplianceStatus::Pass);
    }
}

/// FNV-1a 64 — the digest every substrate in the SuperInstance fleet agrees on.
pub const FNV_OFFSET: u64 = 0xcbf29ce484222325;
pub const FNV_PRIME: u64 = 0x100000001b3;

#[inline]
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h = (h ^ b as u64).wrapping_mul(FNV_PRIME);
    }
    h
}

/// True if this crate's FNV-1a still agrees with the rest of the fleet.
pub fn canary_holds() -> bool {
    fnv1a64("café Δ 日本語".as_bytes()) == 0x024a555471370b18d
}
