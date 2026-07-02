use crate::auditor::Auditor;
use shared::{SecurityEvent, Severity};
use anyhow::{Result, Context};
use async_trait::async_trait;
use mlua::{Lua, Function, StdLib};
use std::fs;

pub struct LuaPluginAuditor {
    pub script_path: String,
}

#[async_trait]
impl Auditor for LuaPluginAuditor {
    fn name(&self) -> String {
        format!("Lua Plugin: {}", self.script_path)
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    async fn execute(&self, target: &str) -> Result<SecurityEvent> {
        let script_code = fs::read_to_string(&self.script_path)
            .with_context(|| format!("Failed to read lua script: {}", self.script_path))?;
        
        let target_clone = target.to_string();
        let check_name = self.name();
        
        let result = tokio::task::spawn_blocking(move || -> Result<(bool, String)> {
            // Only load the base, table, string, and math libraries. 
            // Do NOT load StdLib::OS or StdLib::IO
            let lua = Lua::new_with(StdLib::TABLE | StdLib::STRING | StdLib::MATH, mlua::LuaOptions::new())?;
            lua.load(&script_code).exec()?;
            
            let eval_fn: Function = lua.globals().get("evaluate")?;
            
            let table = lua.create_table()?;
            table.set("target", target_clone)?;
            
            let (is_vuln, details): (bool, String) = eval_fn.call(table)?;
            Ok((is_vuln, details))
        }).await??;

        Ok(SecurityEvent::SimulationAlert {
            target: target.to_string(),
            check_name,
            severity: self.severity(),
            is_vulnerable: result.0,
            details: result.1,
        })
    }
}
