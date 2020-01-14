use std::collections::HashMap;

use lazy_static::lazy_static;

use crate::spf::evaluate_macro;
use crate::spf::MacroVariable;

lazy_static! {
    static ref DEFAULT_OPTIONS_MAP: HashMap<MacroVariable, &'static str> = {
        let mut m = HashMap::new();
        m.insert(MacroVariable::Sender, "sender");
        m.insert(MacroVariable::DomainNameOfHostPerformingTheCheck, "a.b.c.d");
        m
    };
}

pub fn fuzz_evaluate_macro(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = evaluate_macro(&*DEFAULT_OPTIONS_MAP, text);
    }
}
