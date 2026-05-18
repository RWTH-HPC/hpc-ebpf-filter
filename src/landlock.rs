use anyhow::Result;
use landlock::{
    Access, AccessFs, AccessNet, CompatLevel, Compatible, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, Scope,
};
use log::info;

pub fn init_landlock() -> Result<()> {
    let abi = landlock::ABI::V6;
    let ruleset = landlock::Ruleset::default();
    let status = ruleset
        .handle_access(AccessFs::from_all(abi))?
        .handle_access(AccessNet::from_all(abi))?
        .scope(Scope::from_all(abi))?
        .set_compatibility(CompatLevel::BestEffort)
        .create()?
        .set_no_new_privs(true)
        .restrict_self()?;
    match status.ruleset {
        RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced => {
            info!("Landlock sandboxing enabled.");
        }
        RulesetStatus::NotEnforced => {
            info!("Failed to enable landlock, is the kernel too old?");
        }
    }
    Ok(())
}
