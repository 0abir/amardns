pub const DASHBOARD_HTML: &str = include_str!("dashboard.html");

pub fn render_dashboard(key: &str, machine_id: &str, region: &str) -> String {
    let safe_key = key.replace('\\', "\\\\").replace('\'', "\\'").replace('<', "\\x3c").replace('>', "\\x3e");
    let safe_machine = machine_id.replace('\\', "\\\\").replace('\'', "\\'").replace('<', "\\x3c").replace('>', "\\x3e");
    let safe_region = region.replace('\\', "\\\\").replace('\'', "\\'").replace('<', "\\x3c").replace('>', "\\x3e");

    DASHBOARD_HTML
        .replace("var _KEY='';", &format!("var _KEY='{}';", safe_key))
        .replace("var _CURRENT_MACHINE_ID='';", &format!("var _CURRENT_MACHINE_ID='{}';", safe_machine))
        .replace("var _FLY_REGION='';", &format!("var _FLY_REGION='{}';", safe_region))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_dashboard_sanitization() {
        let rendered = render_dashboard("test'key<script>", "m_123'id", "iad");
        assert!(rendered.contains(r"var _KEY='test\'key\x3cscript\x3e';"));
        assert!(rendered.contains(r"var _CURRENT_MACHINE_ID='m_123\'id';"));
        assert!(rendered.contains(r"var _FLY_REGION='iad';"));
    }
}

