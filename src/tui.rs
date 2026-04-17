//! Interactive TUI for blazehash using ratatui + crossterm.
//!
//! Architecture:
//! - Main thread: ratatui event loop (render + input)
//! - Worker thread: sequential file hashing, sends `TuiEvent` via mpsc channel

use crate::algorithm::Algorithm;
use crate::hash::{hash_file, FileHashResult};
use crate::walk::walk_paths;
use crate::walk_filter::WalkFilter;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Events sent from the worker thread to the TUI render thread.
#[derive(Debug)]
pub enum TuiEvent {
    FileStarted {
        path: String,
    },
    FileCompleted(HashProgress),
    Error {
        path: String,
        error: String,
    },
    Finished {
        total_files: usize,
        total_bytes: u64,
    },
}

/// Progress info for a completed file.
#[derive(Debug)]
pub struct HashProgress {
    pub path: String,
    pub size: u64,
    pub hash_preview: String,
}

/// TUI application state.
struct App {
    current_file: String,
    completed: Vec<HashProgress>,
    processed_bytes: u64,
    total_bytes: u64,
    processed_files: usize,
    total_files: usize,
    start_time: Instant,
    finished: bool,
}

/// Run the interactive TUI.
pub fn run_tui(
    paths: &[PathBuf],
    algorithms: &[Algorithm],
    recursive: bool,
    _filter: &WalkFilter,
    entropy: bool,
) -> Result<Vec<FileHashResult>> {
    use crossterm::{
        event::{self, Event, KeyCode},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::{
        backend::CrosstermBackend,
        layout::{Constraint, Direction, Layout},
        style::{Color, Style},
        widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
        Terminal,
    };

    // Collect all file paths
    let mut all_paths: Vec<PathBuf> = Vec::new();
    for path in paths {
        if path.is_file() {
            all_paths.push(path.clone());
        } else if path.is_dir() {
            let (file_paths, _errors) = walk_paths(path, recursive);
            all_paths.extend(file_paths);
        }
    }

    let total_bytes: u64 = all_paths
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    let total_files = all_paths.len();

    let (tx, rx) = mpsc::channel::<TuiEvent>();

    // Spawn worker thread
    let algos = algorithms.to_vec();
    let worker_paths = all_paths.clone();
    let worker = std::thread::spawn(move || -> Vec<FileHashResult> {
        let mut results = Vec::new();
        for path in &worker_paths {
            let _ = tx.send(TuiEvent::FileStarted {
                path: path.display().to_string(),
            });
            match hash_file(path, &algos, false, false, entropy, crate::hash::YaraOpts::no_yara()) {
                Ok(result) => {
                    let preview = result
                        .hashes
                        .values()
                        .next()
                        .map(|h| {
                            if h.len() > 16 {
                                format!("{}...", &h[..16])
                            } else {
                                h.clone()
                            }
                        })
                        .unwrap_or_default();
                    let _ = tx.send(TuiEvent::FileCompleted(HashProgress {
                        path: path.display().to_string(),
                        size: result.size,
                        hash_preview: preview,
                    }));
                    results.push(result);
                }
                Err(e) => {
                    let _ = tx.send(TuiEvent::Error {
                        path: path.display().to_string(),
                        error: e.to_string(),
                    });
                }
            }
        }
        let total_bytes_done: u64 = results.iter().map(|r| r.size).sum();
        let _ = tx.send(TuiEvent::Finished {
            total_files: results.len(),
            total_bytes: total_bytes_done,
        });
        results
    });

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App {
        current_file: String::new(),
        completed: Vec::new(),
        total_bytes,
        processed_bytes: 0,
        total_files,
        processed_files: 0,
        start_time: Instant::now(),
        finished: false,
    };

    loop {
        // Drain events from worker
        while let Ok(evt) = rx.try_recv() {
            match evt {
                TuiEvent::FileStarted { path } => {
                    app.current_file = path;
                }
                TuiEvent::FileCompleted(progress) => {
                    app.processed_bytes += progress.size;
                    app.processed_files += 1;
                    if app.completed.len() >= 20 {
                        app.completed.remove(0);
                    }
                    app.completed.push(progress);
                }
                TuiEvent::Error { path, error } => {
                    if app.completed.len() >= 20 {
                        app.completed.remove(0);
                    }
                    app.completed.push(HashProgress {
                        path: format!("[ERR] {path}: {error}"),
                        size: 0,
                        hash_preview: String::new(),
                    });
                }
                TuiEvent::Finished { .. } => {
                    app.finished = true;
                }
            }
        }

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Min(5),
                ])
                .split(f.area());

            let title = Paragraph::new(format!("blazehash  {}", app.current_file))
                .block(Block::default().borders(Borders::ALL).title(" Hashing "));
            f.render_widget(title, chunks[0]);

            let ratio = if app.total_bytes > 0 {
                (app.processed_bytes as f64 / app.total_bytes as f64).min(1.0)
            } else {
                0.0
            };
            let gauge = Gauge::default()
                .block(Block::default().borders(Borders::ALL).title(" Progress "))
                .gauge_style(Style::default().fg(Color::Green))
                .ratio(ratio)
                .label(format!("{}/{} files", app.processed_files, app.total_files));
            f.render_widget(gauge, chunks[1]);

            let elapsed = app.start_time.elapsed().as_secs_f64().max(0.001);
            let mbps = app.processed_bytes as f64 / (1024.0 * 1024.0) / elapsed;
            let stats = Paragraph::new(format!(" {mbps:.1} MB/s  elapsed: {elapsed:.1}s"))
                .block(Block::default().borders(Borders::ALL).title(" Stats "));
            f.render_widget(stats, chunks[2]);

            let items: Vec<ListItem> = app
                .completed
                .iter()
                .rev()
                .map(|p| ListItem::new(format!("{} ({} bytes)", p.path, p.size)))
                .collect();
            let list =
                List::new(items).block(Block::default().borders(Borders::ALL).title(" Recent "));
            f.render_widget(list, chunks[3]);
        })?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                    break;
                }
            }
        }

        if app.finished {
            std::thread::sleep(Duration::from_secs(1));
            break;
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

    let results = worker
        .join()
        .map_err(|_| anyhow::anyhow!("worker thread panicked"))?;
    Ok(results)
}
