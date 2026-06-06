//! `fp-compare` — pairwise n-gram fingerprint comparison CLI.
//!
//! Operator-facing diagnostic: takes two byte-streams (raw .bin или
//! .pcap captures) и prints chi² / KL-divergence + а pass/fail signal
//! against а configurable threshold.
//!
//! ## Usage
//!
//! ```text
//! fp-compare [OPTIONS] <SAMPLE> <REFERENCE>
//!
//! ARGS:
//!   <SAMPLE>     Path к the sample byte stream (your veil capture).
//!   <REFERENCE>  Path к the reference byte stream (Chrome HTTPS, uniform
//!                random, или another veil run).
//!
//! OPTIONS:
//!   --n <N>            N-gram length 1..=4 (default 1 = unigram).
//!   --port <PORT>      Filter pcap by TCP/UDP port (either src or dst).
//!                      Ignored для raw .bin files.
//!   --threshold <CHI²> Pass/fail threshold for chi-squared (default 0.05).
//!                      Sample chi² < threshold ⇒ pass (looks like ref).
//!   --pcap-sample      Treat SAMPLE as а pcap file.
//!   --pcap-reference   Treat REFERENCE as а pcap file.
//! ```
//!
//! ## Exit codes
//!
//! - 0 — chi² и KL both below threshold (pass; sample looks like reference).
//! - 1 — chi² OR KL above threshold (fail; statistically distinguishable).
//! - 2 — usage error / I/O failure / corrupted input.
//!
//! Use в CI / regression scripts:
//!
//! ```bash
//! cargo run -p veil-fingerprint --features pcap --bin fp-compare -- \
//!   --pcap-sample --pcap-reference --port 5556 --threshold 0.01 \
//!   veil-sample.pcap chrome-reference.pcap
//! echo "exit code: $?"
//! ```

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use veil_fingerprint::{NGramModel, chi_squared, kl_divergence};

#[derive(Debug)]
struct Args {
    sample_path: PathBuf,
    reference_path: PathBuf,
    n: usize,
    port_filter: Option<u16>,
    threshold: f64,
    pcap_sample: bool,
    pcap_reference: bool,
}

fn print_usage() {
    eprintln!(
        "fp-compare — pairwise n-gram fingerprint comparison\n\n\
         USAGE: fp-compare [OPTIONS] <SAMPLE> <REFERENCE>\n\n\
         OPTIONS:\n  \
           --n <N>            N-gram length (default 1)\n  \
           --port <PORT>      Filter pcap by TCP/UDP port\n  \
           --threshold <X>    Chi² pass/fail threshold (default 0.05)\n  \
           --pcap-sample      Parse SAMPLE as pcap (.pcap/.pcapng)\n  \
           --pcap-reference   Parse REFERENCE as pcap\n\n\
         EXIT CODES:\n  \
           0 — chi² и KL both below threshold (pass)\n  \
           1 — distinguishable (fail)\n  \
           2 — I/O error or usage error"
    );
}

fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.is_empty() {
        return Err("missing arguments".into());
    }

    let mut sample_path: Option<PathBuf> = None;
    let mut reference_path: Option<PathBuf> = None;
    let mut n = 1usize;
    let mut port_filter: Option<u16> = None;
    let mut threshold = 0.05;
    let mut pcap_sample = false;
    let mut pcap_reference = false;

    let mut i = 0;
    while i < raw.len() {
        let arg = &raw[i];
        match arg.as_str() {
            "--n" => {
                i += 1;
                n = raw
                    .get(i)
                    .ok_or("--n needs а value")?
                    .parse()
                    .map_err(|e| format!("--n: {e}"))?;
            }
            "--port" => {
                i += 1;
                port_filter = Some(
                    raw.get(i)
                        .ok_or("--port needs а value")?
                        .parse()
                        .map_err(|e| format!("--port: {e}"))?,
                );
            }
            "--threshold" => {
                i += 1;
                threshold = raw
                    .get(i)
                    .ok_or("--threshold needs а value")?
                    .parse()
                    .map_err(|e| format!("--threshold: {e}"))?;
            }
            "--pcap-sample" => pcap_sample = true,
            "--pcap-reference" => pcap_reference = true,
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            a if a.starts_with("--") => {
                return Err(format!("unknown option: {a}"));
            }
            _ => {
                if sample_path.is_none() {
                    sample_path = Some(PathBuf::from(arg));
                } else if reference_path.is_none() {
                    reference_path = Some(PathBuf::from(arg));
                } else {
                    return Err(format!("unexpected positional argument: {arg}"));
                }
            }
        }
        i += 1;
    }

    Ok(Args {
        sample_path: sample_path.ok_or("missing SAMPLE positional argument")?,
        reference_path: reference_path.ok_or("missing REFERENCE positional argument")?,
        n,
        port_filter,
        threshold,
        pcap_sample,
        pcap_reference,
    })
}

fn load_into_model(
    path: &std::path::Path,
    is_pcap: bool,
    port_filter: Option<u16>,
    n: usize,
) -> Result<NGramModel, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut model = NGramModel::new(n);

    if is_pcap {
        #[cfg(feature = "pcap")]
        {
            veil_fingerprint::pcap::observe_pcap(&mut model, file, port_filter)
                .map_err(|e| format!("pcap parse {}: {e}", path.display()))?;
        }
        #[cfg(not(feature = "pcap"))]
        {
            let _ = port_filter; // suppress unused-var warning
            return Err(format!(
                "{}: pcap support not compiled in — rebuild с --features pcap",
                path.display()
            ));
        }
    } else {
        let _ = port_filter; // raw-bin path doesn't filter
        let mut buf = Vec::new();
        let mut file = file;
        file.read_to_end(&mut buf)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        model.observe(&buf);
    }
    Ok(model)
}

fn run(args: Args) -> Result<bool, String> {
    if !(1..=4).contains(&args.n) {
        return Err(format!("--n must be in 1..=4, got {}", args.n));
    }

    let sample = load_into_model(
        &args.sample_path,
        args.pcap_sample,
        args.port_filter,
        args.n,
    )?;
    let reference = load_into_model(
        &args.reference_path,
        args.pcap_reference,
        args.port_filter,
        args.n,
    )?;

    println!("Sample:    {}", args.sample_path.display());
    println!("  n-grams observed: {}", sample.total_count());
    println!("  distinct:         {}", sample.distinct_ngrams());
    println!("Reference: {}", args.reference_path.display());
    println!("  n-grams observed: {}", reference.total_count());
    println!("  distinct:         {}", reference.distinct_ngrams());
    println!();

    let chi = chi_squared(&sample, &reference);
    let kl = kl_divergence(&sample, &reference);

    println!("chi-squared distance: {chi:.6}");
    println!("KL divergence:        {kl:.6}");
    println!("threshold:            {:.6}", args.threshold);
    println!();

    let pass = chi < args.threshold && kl < args.threshold;
    if pass {
        println!("✅ PASS — sample statistically indistinguishable from reference");
    } else {
        println!("❌ FAIL — sample distinguishable from reference");
        if chi >= args.threshold {
            println!("  chi² {chi:.6} ≥ threshold {:.6}", args.threshold);
        }
        if kl >= args.threshold {
            println!("  KL   {kl:.6} ≥ threshold {:.6}", args.threshold);
        }
    }
    Ok(pass)
}

fn main() -> ExitCode {
    match parse_args() {
        Err(e) => {
            eprintln!("error: {e}\n");
            print_usage();
            ExitCode::from(2)
        }
        Ok(args) => match run(args) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        },
    }
}
