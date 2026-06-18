mod candidates;
mod metadata;
mod verdict;

use crate::models::{DefenderEvent, FileScore, RegistryEntry, ScheduledTask, StartupEntry};

pub(crate) fn scan_file_scores(
    registry_entries: &[RegistryEntry],
    startup_entries: &[StartupEntry],
    tasks: &[ScheduledTask],
    defender_events: &[DefenderEvent],
) -> Vec<FileScore> {
    let candidates = candidates::collect_candidates(registry_entries, startup_entries, tasks);
    if candidates.is_empty() {
        return vec![];
    }

    let meta = metadata::load_metadata(&candidates);
    let mut scores: Vec<FileScore> = candidates
        .into_iter()
        .map(|(path, source)| {
            let file_meta = meta.get(&path.to_lowercase());
            verdict::build_score(path, source, file_meta, defender_events)
        })
        .collect();

    scores.sort_by(|a, b| b.score.cmp(&a.score));
    scores
}
