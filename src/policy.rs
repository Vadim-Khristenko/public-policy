use anyhow::Result;

use crate::generator::{self, PolicyGenerationRequest};

pub fn generate_policy(request: PolicyGenerationRequest<'_>) -> Result<String> {
    generator::generate_policy(request)
}
