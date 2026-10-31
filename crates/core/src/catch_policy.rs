//! How a KIRun step marked `catchErrors` treats a failure in core: a run stopped at its limits
//! (`exec_limit`) is never caught, so the limit's answer wins; a failure a core function raised
//! names its own code as the event's `reason`, and is taken off the request, so a run that goes
//! on and fails later is not answered with it.

use std::sync::Arc;

use kirun::runtime::catch_errors::{set_policy, Caught};

/// Installs the policy for this process (once is enough; again replaces it).
pub fn install() {
    set_policy(Some(Arc::new(|err: &kirun::KIRunError| {
        if crate::exec_limit::stopped() {
            return Caught::Rethrow;
        }
        let text = err.to_string();
        let reason = crate::context::request().and_then(|r| {
            let mut raised = r.raised.lock();
            let code = raised.as_ref().filter(|c| c.text() == text).and_then(|c| c.code().map(|c| c.code.to_string()));
            if code.is_some() {
                *raised = None;
            }
            code
        });
        Caught::Event { reason }
    })));
}
