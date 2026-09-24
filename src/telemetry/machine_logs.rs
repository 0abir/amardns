use parking_lot::Mutex;
use std::collections::VecDeque;

static MACHINE_LOGS: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
const MAX_MACHINE_LOGS: usize = 300;

pub struct DashboardLogLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for DashboardLogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = LogMessageVisitor::default();
        event.record(&mut visitor);
        let meta = event.metadata();
        let level = meta.level();
        let target = meta.target();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
        let line = format!("{} {:5} {}: {}", now, level, target, visitor.message);

        let mut logs = MACHINE_LOGS.lock();
        if logs.len() >= MAX_MACHINE_LOGS {
            logs.pop_front();
        }
        logs.push_back(line);
    }
}

pub fn get_machine_logs() -> Vec<String> {
    let logs = MACHINE_LOGS.lock();
    logs.iter().cloned().collect()
}

#[allow(dead_code)]
pub fn clear_machine_logs() {
    let mut logs = MACHINE_LOGS.lock();
    logs.clear();
}

#[derive(Default)]
struct LogMessageVisitor {
    message: String,
}

impl tracing::field::Visit for LogMessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let s = format!("{:?}", value);
            self.message = if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
                s[1..s.len() - 1].to_string()
            } else {
                s
            };
        } else if self.message.is_empty() {
            self.message = format!("{}: {:?}", field.name(), value);
        } else {
            self.message.push_str(&format!(" {}={:?}", field.name(), value));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else if self.message.is_empty() {
            self.message = format!("{}: {}", field.name(), value);
        } else {
            self.message.push_str(&format!(" {}={}", field.name(), value));
        }
    }
}
