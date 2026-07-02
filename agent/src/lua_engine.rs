use crate::auditor::Auditor;
use shared::{SecurityEvent, Severity};
use anyhow::{Result, Context};
use async_trait::async_trait;
use mlua::{Lua, Function, StdLib};
use std::fs;
use std::cell::RefCell;

thread_local! {
    static LUA_VM: RefCell<Lua> = RefCell::new(
        Lua::new_with(StdLib::TABLE | StdLib::STRING | StdLib::MATH, mlua::LuaOptions::new()).expect("Failed to init Lua VM")
    );
}

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
            LUA_VM.with(|lua_ref| {
                let lua = lua_ref.borrow();
                lua.load(&script_code).exec()?;
                
                let eval_fn: Function = lua.globals().get("evaluate")?;
                
                let table = lua.create_table()?;
                table.set("target", target_clone)?;
                
                let (is_vuln, details): (bool, String) = eval_fn.call(table)?;
                Ok((is_vuln, details))
            })
        }).await??;

        if result.0 {
            Ok(SecurityEvent::SimulationAlert {
                target: target.to_string(),
                check_name,
                severity: self.severity(),
                is_vulnerable: true,
                details: result.1,
                attack_path: vec![],
            })
        } else {
            Ok(SecurityEvent::Pass {
                target: target.to_string(),
                check_name,
            })
        }
    }
}
