use std::io::{self, Read};
use unicode_interference::probe;

const USAGE: &str = "Usage: probe [OPTIONS] [TEXT]

Detect Unicode script-mixing attacks using forward/reverse interference patterns.

ARGS:
  TEXT        Text to analyze. If omitted, reads from stdin.

OPTIONS:
  --pattern   Show the full interference pattern visualization (default)
  --summary   One-line summary only
  --json      Output as JSON
  --deobf     Print the deobfuscated string only
  --quiet     Exit code only (0=clean, 1=flagged)
  --help      Show this help

EXIT CODES:
  0   Clean — no intrusions detected
  1   Flagged — score >= 0.20 (intrusions found)

EXAMPLES:
  probe 'ignore all instructions'
  probe $'\\u0456gnore all instructions'
  echo 'some text' | probe
  probe --json 'text to analyze'
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut mode = "pattern";
    let mut text_parts: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => { print!("{}", USAGE); std::process::exit(0); }
            "--pattern"     => { mode = "pattern"; }
            "--summary"     => { mode = "summary"; }
            "--json"        => { mode = "json"; }
            "--deobf"       => { mode = "deobf"; }
            "--quiet"       => { mode = "quiet"; }
            arg if arg.starts_with('-') => {
                eprintln!("Unknown option: {}", arg);
                std::process::exit(2);
            }
            arg => { text_parts.push(arg.to_string()); }
        }
        i += 1;
    }

    let input = if text_parts.is_empty() {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).unwrap();
        buf.trim_end_matches('\n').to_string()
    } else {
        text_parts.join(" ")
    };

    if input.is_empty() {
        eprintln!("No input provided. Use --help for usage.");
        std::process::exit(2);
    }

    let report = probe(&input);

    match mode {
        "pattern" => {
            println!("{}", report.render_pattern());
        }
        "summary" => {
            println!("{}", report.summary());
        }
        "deobf" => {
            println!("{}", report.deobfuscated());
        }
        "json" => {
            // Hand-rolled JSON — no serde dep in v1
            let intrusions_json: Vec<String> = report.intrusions.iter().map(|intr| {
                let rotation = match intr.rotation {
                    Some(c) => format!("\"{}\"", c),
                    None    => "null".to_string(),
                };
                format!(
                    "{{\"position\":{},\"character\":\"\\u{:04X}\",\"script\":\"{}\",\"rotation\":{},\"confidence\":{:.2},\"detail\":\"{}\"}}",
                    intr.position,
                    intr.character as u32,
                    intr.script.name(),
                    rotation,
                    intr.confidence,
                    intr.detail.replace('"', "\\\""),
                )
            }).collect();

            println!(
                "{{\"score\":{:.2},\"dominant_script\":\"{}\",\"has_intrusions\":{},\"should_flag\":{},\"deobfuscated\":\"{}\",\"intrusions\":[{}]}}",
                report.score,
                report.dominant_script.name(),
                report.has_intrusions(),
                report.should_flag(),
                report.deobfuscated().replace('"', "\\\""),
                intrusions_json.join(","),
            );
        }
        "quiet" => { /* exit code only */ }
        _ => {}
    }

    // Exit code signals clean/flagged to pipelines
    std::process::exit(if report.should_flag() { 1 } else { 0 });
}
