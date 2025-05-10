use clap::{Arg, Command};
use colored::Colorize;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::BorderType,
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs},
};
use std::{
    io,
    path::Path,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use crate::static_analysis::{
    analyze_callgraph, decompile_binary, disassemble_binary, extract_metadata, analyze_binary,
};

const RUSTYBOX_ASCII: &str = r#"
 ____            _         ____            
|  _ \ _   _ ___| |_ _   _| __ )  _____  __
| |_) | | | / __| __| | | |  _ \ / _ \ \/ /
|  _ <| |_| \__ \ |_| |_| | |_) | (_) >  < 
|_| \_\\__,_|___/\__|\__, |____/ \___/_/\_\
                     |___/                 
       Express Binary Analysis Tool
"#;

enum AnalysisMode {
    Metadata,
    Disassembly,
    Decompile,
    Callgraph,
}

struct AnalysisResult {
    metadata: Option<Result<String, String>>,
    disassembly: Option<Result<String, String>>,
    decompile: Option<Result<String, String>>,
    callgraph: Option<Result<String, String>>,
}

#[allow(dead_code)]
struct App {
    selected_tab: usize,
    analysis_results: AnalysisResult,
    file_path: String,
    instr_count: u32,
    verbose: bool,
    scroll_position: u16,
}

impl App {
    fn new(file_path: String, instr_count: u32, verbose: bool) -> Self {
        Self {
            selected_tab: 0,
            analysis_results: AnalysisResult {
                metadata: None,
                disassembly: None,
                decompile: None,
                callgraph: None,
            },
            file_path,
            instr_count,
            verbose,
            scroll_position: 0,
        }
    }

    fn tab_titles(&self) -> Vec<String> {
        vec![
            "Metadata".to_string(),
            "Disassembly".to_string(),
            "Decompile".to_string(),
            "Callgraph".to_string(),
        ]
    }

    fn next_tab(&mut self) {
        self.selected_tab = (self.selected_tab + 1) % 4;
    }

    fn previous_tab(&mut self) {
        self.selected_tab = (self.selected_tab + 3) % 4;
    }

    fn get_current_result_text(&self) -> String {
        match self.selected_tab {
            0 => match &self.analysis_results.metadata {
                Some(Ok(text)) => text.clone(),
                Some(Err(e)) => format!("Error: {}", e),
                None => "Loading metadata...".to_string(),
            },
            1 => match &self.analysis_results.disassembly {
                Some(Ok(text)) => text.clone(),
                Some(Err(e)) => format!("Error: {}", e),
                None => "Loading disassembly...".to_string(),
            },
            2 => match &self.analysis_results.decompile {
                Some(Ok(text)) => text.clone(),
                Some(Err(e)) => format!("Error: {}", e),
                None => "Loading decompiled code...".to_string(),
            },
            3 => match &self.analysis_results.callgraph {
                Some(Ok(text)) => text.clone(),
                Some(Err(e)) => format!("Error: {}", e),
                None => "Loading callgraph...".to_string(),
            },
            _ => "Unknown tab".to_string(),
        }
    }
    fn scroll_down(&mut self) {
        let max_scroll = self.get_max_scroll();
        if self.scroll_position < max_scroll {
            self.scroll_position += 1;
        }
    }

    fn scroll_up(&mut self) {
        if self.scroll_position > 0 {
            self.scroll_position -= 1;
        }
    }

    fn page_down(&mut self) {
        let max_scroll = self.get_max_scroll();
        self.scroll_position = (self.scroll_position + 10).min(max_scroll);
    }

    fn page_up(&mut self) {
        self.scroll_position = self.scroll_position.saturating_sub(10);
    }

    fn scroll_to_top(&mut self) {
        self.scroll_position = 0;
    }

    fn scroll_to_bottom(&mut self) {
        self.scroll_position = self.get_max_scroll();
    }

    fn get_max_scroll(&self) -> u16 {
        let content = self.get_current_result_text();
        let line_count = content.lines().count() as u16;

        let terminal_height = crossterm::terminal::size().unwrap_or((0, 24)).1;
        let content_height = terminal_height.saturating_sub(6);

        if line_count <= content_height {
            return 0;
        }

        line_count.saturating_sub(content_height)
    }
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let matches = create_cli().get_matches();

    let file_path = matches.get_one::<String>("FILE").unwrap();

    if !Path::new(file_path).exists() {
        return Err(format!("File does not exist: {}", file_path).into());
    }
    let is_flag_used = matches.get_flag("no-tui")
        || matches.get_flag("metadata")
        || matches.get_flag("disassemble")
        || matches.get_flag("decompile")
        || matches.get_flag("callgraph")
        || matches.contains_id("log-file");

    if is_flag_used {
        return run_standard_cli(matches);
    }

    // Otherwise, run the TUI interface
    run_tui(
        file_path.clone(),
        matches.get_one::<u32>("count").copied().unwrap_or(20),
        matches.get_flag("verbose"),
    )
}

fn run_standard_cli(matches: clap::ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let file_path = matches.get_one::<String>("FILE").unwrap();

    println!("{}", RUSTYBOX_ASCII.truecolor(225, 95, 80).bold());


    if matches.get_flag("binaryp") {
        if let Err(e) = crate::static_analysis::analyze_binary(file_path) {
            eprintln!("Error analyzing binary: {}", e);
        }
        return Ok(()); // Exit after running the binaryp command
    }


    let run_all = !matches.get_flag("disassemble")
        && !matches.get_flag("metadata")
        && !matches.get_flag("decompile")
        && !matches.get_flag("callgraph");

    let mut results_found = false;

    // Metadata Analysis
    if run_all || matches.get_flag("metadata") {
        results_found = true;
        println!("{}", "\n[+] Binary Metadata Analysis".green().bold());
        println!("{}", "=========================".green());

        match extract_metadata(file_path) {
            Ok(metadata) => {
                println!("Format: {}", metadata.format);
                if let Some(entry) = metadata.entry_point {
                    println!("Entry Point: {:#x}", entry);
                }
                if let Some(sections) = metadata.sections {
                    println!("Number of Sections: {}", sections);
                }
                if let Some(ph) = metadata.program_headers {
                    println!("Program Headers: {}", ph);
                }
                if let Some(machine) = &metadata.machine {
                    println!("Machine Type: {}", machine);
                }
                if let Some(image_base) = metadata.image_base {
                    println!("Image Base: {:#x}", image_base);
                }
                if let Some(is_64) = metadata.is_64 {
                    println!("64-bit: {}", is_64);
                }
                if let Some(load_cmds) = metadata.load_commands {
                    println!("Load Commands: {}", load_cmds);
                }
                if let Some(cpu) = &metadata.cpu_type {
                    println!("CPU Type: {}", cpu);
                }
                if let Some(arch_count) = metadata.arch_count {
                    println!("Architecture Count: {}", arch_count);
                }
            }
            Err(e) => {
                eprintln!("{} {}", "[-] Error extracting metadata:".red().bold(), e);
            }
        }
    }

    // Disassembly Analysis
    if run_all || matches.get_flag("disassemble") {
        results_found = true;
        println!("{}", "\n[+] Disassembly".green().bold());
        println!("{}", "=============".green());

        let instr_count = matches.get_one::<u32>("count").copied().unwrap_or(20);

        match disassemble_binary(file_path, instr_count, matches.get_flag("verbose")) {
            Ok(disasm) => println!("{}", disasm),
            Err(e) => eprintln!("Disassembly error: {}", e),
        }
    }

    // Decompilation Analysis
    if run_all || matches.get_flag("decompile") {
        results_found = true;
        println!("{}", "\n[+] Decompiled Code".green().bold());
        println!("{}", "=================".green());

        match decompile_binary(file_path, matches.get_flag("verbose")) {
            Ok(decompiled) => {
                println!("{}", decompiled);
            }
            Err(e) => {
                eprintln!("{} {}", "[-] Error decompiling binary:".red().bold(), e);
            }
        }
    }

    // Callgraph Analysis
    if run_all || matches.get_flag("callgraph") {
        results_found = true;
        println!("{}", "\n[+] Function Call Graph".green().bold());
        println!("{}", "====================".green());

        match analyze_callgraph(file_path) {
            Ok(graph) => {
                println!("{}", graph);
            }
            Err(e) => {
                eprintln!("{} {}", "[-] Error generating call graph:".red().bold(), e);
            }
        }
    }

    if !results_found {
        println!(
            "{}",
            "No analysis was performed. Use '--help' to see available options.".yellow()
        );
    }

    Ok(())
}

fn run_tui(
    file_path: String,
    instr_count: u32,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", RUSTYBOX_ASCII.truecolor(225, 95, 80).bold());
    std::thread::sleep(Duration::from_secs(2));
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(file_path.clone(), instr_count, verbose);

    let (tx, rx) = mpsc::channel();
    let file_path_clone = file_path.clone();
    let instr_count_clone = instr_count;
    let verbose_clone = verbose;

    thread::spawn(move || {
        // Run all analyses in sequence
        // Metadata
        let metadata_result = match extract_metadata(&file_path_clone) {
            Ok(metadata) => {
                let mut output = String::new();
                output.push_str(&format!("Format: {}\n", metadata.format));
                if let Some(entry) = metadata.entry_point {
                    output.push_str(&format!("Entry Point: {:#x}\n", entry));
                }
                if let Some(sections) = metadata.sections {
                    output.push_str(&format!("Number of Sections: {}\n", sections));
                }
                if let Some(ph) = metadata.program_headers {
                    output.push_str(&format!("Program Headers: {}\n", ph));
                }
                if let Some(machine) = &metadata.machine {
                    output.push_str(&format!("Machine Type: {}\n", machine));
                }
                if let Some(image_base) = metadata.image_base {
                    output.push_str(&format!("Image Base: {:#x}\n", image_base));
                }
                if let Some(is_64) = metadata.is_64 {
                    output.push_str(&format!("64-bit: {}\n", is_64));
                }
                if let Some(load_cmds) = metadata.load_commands {
                    output.push_str(&format!("Load Commands: {}\n", load_cmds));
                }
                if let Some(cpu) = &metadata.cpu_type {
                    output.push_str(&format!("CPU Type: {}\n", cpu));
                }
                if let Some(arch_count) = metadata.arch_count {
                    output.push_str(&format!("Architecture Count: {}\n", arch_count));
                }
                Ok(output)
            }
            Err(e) => Err(e.to_string()),
        };
        tx.send((AnalysisMode::Metadata, metadata_result)).unwrap();

        // Disassembly
        let disasm_result =
            match disassemble_binary(&file_path_clone, instr_count_clone, verbose_clone) {
                Ok(disasm) => Ok(disasm),
                Err(e) => Err(e.to_string()),
            };
        tx.send((AnalysisMode::Disassembly, disasm_result)).unwrap();

        // Decompile
        let decompile_result = match decompile_binary(&file_path_clone, verbose_clone) {
            Ok(decompiled) => Ok(decompiled),
            Err(e) => Err(e.to_string()),
        };
        tx.send((AnalysisMode::Decompile, decompile_result))
            .unwrap();

        // Callgraph
        let callgraph_result = match analyze_callgraph(&file_path_clone) {
            Ok(graph) => Ok(graph),
            Err(e) => Err(e.to_string()),
        };
        tx.send((AnalysisMode::Callgraph, callgraph_result))
            .unwrap();
    });

    // Main loop
    let tick_rate = Duration::from_millis(250);
    let mut last_tick = Instant::now();

    loop {
        // Check for results from worker thread
        if let Ok((mode, result)) = rx.try_recv() {
            match mode {
                AnalysisMode::Metadata => app.analysis_results.metadata = Some(result),
                AnalysisMode::Disassembly => app.analysis_results.disassembly = Some(result),
                AnalysisMode::Decompile => app.analysis_results.decompile = Some(result),
                AnalysisMode::Callgraph => app.analysis_results.callgraph = Some(result),
            }
        }

        // Draw the UI
        terminal.draw(|f| draw_ui(f, &app))?;

        // Handle input
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Right | KeyCode::Tab => app.next_tab(),
                    KeyCode::Left | KeyCode::BackTab => app.previous_tab(),
                    KeyCode::Char('1') => app.selected_tab = 0,
                    KeyCode::Char('2') => app.selected_tab = 1,
                    KeyCode::Char('3') => app.selected_tab = 2,
                    KeyCode::Char('4') => app.selected_tab = 3,
                    KeyCode::Down => app.scroll_down(),
                    KeyCode::Up => app.scroll_up(),
                    KeyCode::PageDown => app.page_down(),
                    KeyCode::PageUp => app.page_up(),
                    KeyCode::Home => app.scroll_to_top(),
                    KeyCode::End => app.scroll_to_bottom(),
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn draw_ui(f: &mut ratatui::Frame, app: &App) {
    let terminal_size = f.area();

    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(terminal_size);

    let top_bar = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(main_layout[0]);

    let file_info = Paragraph::new(format!(" {}", app.file_path))
        .style(Style::default().fg(Color::Cyan))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title("Target"),
        );

    f.render_widget(file_info, top_bar[0]);

    // Draw tabs
    let titles = app.tab_titles();
    let tab_titles: Vec<Line> = titles
        .iter()
        .map(|t| Line::from(Span::styled(t, Style::default().fg(Color::White))))
        .collect();

    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        )
        .select(app.selected_tab)
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(tabs, top_bar[1]);

    // Content area
    let content_text = app.get_current_result_text();

    let content_title = match app.selected_tab {
        0 => "Binary Metadata",
        1 => "Disassembly",
        2 => "Decompiled Code",
        3 => "Function Call Graph",
        _ => "Unknown",
    };

    let scroll_info = if app.get_max_scroll() > 0 {
        format!(" [{}/{}]", app.scroll_position, app.get_max_scroll())
    } else {
        String::new()
    };

    let content = Paragraph::new(content_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(format!("{}{}", content_title, scroll_info)),
        )
        .style(Style::default().fg(Color::White))
        .wrap(ratatui::widgets::Wrap { trim: true })
        .scroll((app.scroll_position, 0));

    f.render_widget(content, main_layout[1]);

    // Help bar at bottom
    let status = match app.selected_tab {
        0 => "Metadata ▶",
        1 => "Disassembly ▶",
        2 => "Decompile ▶",
        3 => "Callgraph ▶",
        _ => "Unknown",
    };

    let help_text = Line::from(vec![
        Span::styled(
            " q ",
            Style::default()
                .bg(Color::Red)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" quit | "),
        Span::styled(" ←→ ", Style::default().bg(Color::Blue).fg(Color::White)),
        Span::raw(" change view | "),
        Span::styled(" ↑↓ ", Style::default().bg(Color::Blue).fg(Color::White)),
        Span::raw(" scroll | "),
        Span::styled(
            status,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let help_bar = Paragraph::new(help_text).style(Style::default().bg(Color::DarkGray));

    f.render_widget(help_bar, main_layout[2]);
}

fn create_cli() -> Command {
    Command::new("Rustybox")
        .version("0.1.0")
        .author("Rustybox Team")
        .about("A malware analysis tool for static and dynamic analysis")
        .arg(
            Arg::new("FILE")
                .help("Path to the binary file to analyze")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("metadata")
                .long("metadata")
                .short('m')
                .help("Extract metadata from the binary")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("disassemble")
                .long("disassemble")
                .short('d')
                .help("Disassemble the binary")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("count")
                .long("count")
                .short('c')
                .help("Number of instructions to disassemble (default: 20)")
                .value_parser(clap::value_parser!(u32))
                .requires("disassemble"),
        )
        .arg(
            Arg::new("decompile")
                .long("decompile")
                .short('p')
                .help("Decompile the binary to pseudo-code")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("callgraph")
                .long("callgraph")
                .short('g')
                .help("Generate and display the function call graph")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .help("Enable verbose logging output")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("log-file")
                .long("log-file")
                .help("Path to log file (optional)")
                .value_name("FILE"),
        )
        .arg(
            Arg::new("no-tui")
                .long("no-tui")
                .help("Run in classic command-line mode without TUI")
                .action(clap::ArgAction::SetTrue),
        )

        .arg(
            Arg::new("binaryp")
                .long("binaryp")
                .help("Analyze the binary using the binaryp command")
                .action(clap::ArgAction::SetTrue),
        )
}
