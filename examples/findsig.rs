extern crate scanner;
extern crate pelite;

use std::env;
use std::path::Path;
use std::io::{self, BufRead};

use pelite::{pe32, pe64};
use scanner::{Scanner, pat};

const HELP_TEXT: &'static str = "\
Example signature scanner; https://github.com/CasualX/scanner-rs\n\
\n\
FINDSIG <file> [sig]...\n\
\n\
  file  Path to the input binary to scan.\n\
  sig   Any number of signatures to find.\n\
\n\
If no signatures are provided, they are read line by line from stdin.\n";

fn main() {
	// Get args and skip the invoker
	let mut args = env::args();
	args.next();

	// Read the input file
	if let Some(file) = args.next() {
		// Path and filename of the input file
		let path = Path::new(&file);
		let file_name = path.file_name().unwrap().to_str().unwrap();

		// Try reading as PE32
		if let Ok(pe) = pe32::pefile::PeFile::open(&path) {
			// Initialize scanner and dispatch
			let scan = Scanner::from(&pe.view());
			process_sigs(file_name, args, &scan, pat::parse32);
		}
		// Try reading as PE32+
		else if let Ok(pe) = pe64::pefile::PeFile::open(&path) {
			// Initialize scanner and dispatch
			let scan = Scanner::from(&pe.view());
			process_sigs(file_name, args, &scan, pat::parse64);
		}
		// Must be a valid PE binary
		else {
			println!("File not found or not a valid PE binary.");
		}
	}
	else {
		print!("{}", HELP_TEXT);
	}
}

fn process_sigs(file: &str, args: env::Args, scan: &Scanner, parse: fn(&str) -> Result<pat::Pattern, pat::PatError>) {
	let mut stdin = true;
	for sig in args {
		parse_and_find(file, &sig, scan, parse);
		stdin = false;
	}
	// Read from standard input if no signatures were provided on command line
	if stdin {
		let stdin = io::stdin();
		for sig in stdin.lock().lines().filter_map(|line| line.ok()) {
			parse_and_find(file, &sig, scan, parse);
		}
	}
}
fn parse_and_find(file: &str, sig: &str, scan: &Scanner, parse: fn(&str) -> Result<pat::Pattern, pat::PatError>) {
	// Parse the signature in correct bitness
	match parse(sig) {
		Ok(pat) => {
			println!("Pattern \"{}\" matches:", sig);
			// Find and print all matches
			for mach in scan.iter(&pat) {
				println!("  {}!{}", file, mach);
			}
		},
		Err(err) => {
			println!("Pattern \"{}\" error: {:?}", sig, err);
		},
	}
	println!("");
}
