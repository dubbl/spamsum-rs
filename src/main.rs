#[macro_use]
extern crate clap;
use std::fs;
use std::result::Result;

use clap::{App, Arg};

use spamsum::{get_configured_spamsum, SpamsumOptions};

fn main() -> Result<(), &'static str> {
    let matches = App::new("spamsum")
        .version("0.1.0")
        .author("Hauke Lübbers dubbel14@googlemail.com")
        .about("Calculates the spamsum of files")
        .arg(Arg::with_name("input_files").multiple(true).required(true))
        .arg(
            Arg::with_name("blocksize")
                .short("B")
                .long("blocksize")
                .required(false)
                .takes_value(true)
                .help("Set a static blocksize (default is dynamic)"),
        )
        .arg(
            Arg::with_name("ignore_whitespace")
                .short("W")
                .long("ignore-whitespace")
                .required(false)
                .takes_value(false)
                .help("Ignore whitespace"),
        )
        .arg(
            Arg::with_name("ignore_headers")
                .short("H")
                .long("ignore-headers")
                .required(false)
                .takes_value(false)
                .help("Ignore (e-mail) headers"),
        )
        .get_matches();
    let input_files = matches.values_of("input_files");
    let options = SpamsumOptions {
        blocksize: value_t!(matches.value_of("blocksize"), u32).unwrap_or_default(),
        ignore_whitespace: matches.is_present("ignore_whitespace"),
        ignore_headers: matches.is_present("ignore_headers"),
    };
    for input_file in input_files.unwrap() {
        let input = match fs::read(input_file) {
            Ok(file) => file,
            Err(error) => panic!("Could not open the file: {:?}", error),
        };
        let spamsum = match get_configured_spamsum(&input, options) {
            Ok(spamsum) => spamsum,
            Err(e) => return Err(e),
        };
        println!("{}", spamsum);
    }
    Ok(())
}
