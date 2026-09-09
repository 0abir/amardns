pub const DASHBOARD_HTML: &str = include_str!("dashboard.html");

pub fn render_dashboard(key: &str, machine_id: &str, region: &str) -> String {
    DASHBOARD_HTML
        .replace("var _KEY='';", &format!("var _KEY='{}';", key))
        .replace("var _CURRENT_MACHINE_ID='';", &format!("var _CURRENT_MACHINE_ID='{}';", machine_id))
        .replace("var _FLY_REGION='';", &format!("var _FLY_REGION='{}';", region))
}
