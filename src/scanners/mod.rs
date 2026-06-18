mod defender;
mod registry;
mod scheduled;
mod startup;

pub(crate) use defender::scan_defender_logs;
pub(crate) use registry::scan_registry;
pub(crate) use scheduled::scan_scheduled_tasks;
pub(crate) use startup::scan_startup_folder;
