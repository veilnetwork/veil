/// One problem found during config validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationIssue {
    /// Short machine-readable code (e.g. `"missing_field"`, `"pow_too_weak"`).
    pub code: &'static str,
    /// Config key path the issue applies (e.g. `"identity.algo"`).
    pub key: &'static str,
    /// Human-readable description of the problem.
    pub message: String,
    /// `true` iff [`crate::validate_and_fix`] can repair this issue.
    pub can_fix: bool,
}

/// Aggregated result of a validation pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidationReport {
    /// Remaining (non-auto-fixable) issues after any fixes were applied.
    pub issues: Vec<ValidationIssue>,
    /// Count of issues that were auto-fixed during this pass.
    pub fixed: usize,
}

impl ValidationReport {
    /// `true` iff the config passed validation without any remaining issues.
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty()
    }

    /// `true` iff the report carries at least one unresolved issue.
    pub fn has_unfixed_issues(&self) -> bool {
        !self.issues.is_empty()
    }

    /// Render the issue list as a bulleted multi-line string for CLI output.
    pub fn format_issues(&self) -> String {
        self.issues
            .iter()
            .map(|issue| format!("- {}: {}", issue.key, issue.message))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
