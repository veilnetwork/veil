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
    /// A non-empty `issues` list means the config is INVALID
    /// ([`Self::is_valid`] is false).
    pub issues: Vec<ValidationIssue>,
    /// Non-fatal advisories: the config is still valid, but these flag
    /// risky-but-permitted choices the operator should review (e.g. a
    /// fail-open default that is fine for backward-compat but unwise in
    /// production). Warnings NEVER affect [`Self::is_valid`].
    pub warnings: Vec<ValidationIssue>,
    /// Count of issues that were auto-fixed during this pass.
    pub fixed: usize,
}

impl ValidationReport {
    /// `true` iff the config passed validation without any remaining
    /// (fatal) issues. Warnings do not count.
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty()
    }

    /// Promote every non-fatal advisory into a fatal issue and return the
    /// strict report. Used by the production-hardening profile
    /// (`[global].strict_config_validation = true`): a risky-but-permitted
    /// posture (push relay without wake-HMAC, mailbox without capability tokens,
    /// unsigned DHT store, …) becomes a startup-blocking error rather than a
    /// log line. Idempotent; preserves `fixed`.
    pub fn into_strict(mut self) -> Self {
        self.issues.append(&mut self.warnings);
        self
    }

    /// `true` iff the report carries at least one unresolved issue.
    pub fn has_unfixed_issues(&self) -> bool {
        !self.issues.is_empty()
    }

    /// `true` iff the report carries at least one non-fatal advisory.
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Render the issue list as a bulleted multi-line string for CLI output.
    pub fn format_issues(&self) -> String {
        Self::format_list(&self.issues)
    }

    /// Render the non-fatal advisory list as a bulleted multi-line string.
    pub fn format_warnings(&self) -> String {
        Self::format_list(&self.warnings)
    }

    fn format_list(items: &[ValidationIssue]) -> String {
        items
            .iter()
            .map(|issue| format!("- {}: {}", issue.key, issue.message))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
