use std::fmt;
use std::num::Wrapping;
use std::result::Result;

const LEFT_HASH_LENGTH: u32 = 64;
const RIGHT_HASH_LENGTH: u32 = LEFT_HASH_LENGTH / 2;
const MIN_BLOCKSIZE: u32 = 3;
const ROLLING_WINDOW: u32 = 7;
// FNV hash parameters
const HASH_PRIME: Wrapping<u32> = Wrapping(0x01000193);
const HASH_INIT: Wrapping<u32> = Wrapping(0x28021967);

static BASE64_CHARSET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Debug)]
pub struct Spamsum {
    left_hash_blocksize: u32,
    left_hash: String,
    right_hash: String,
}

impl Spamsum {
    #[inline]
    fn right_hash_blocksize(&self) -> u32 {
        self.left_hash_blocksize * 2
    }
}

impl fmt::Display for Spamsum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.left_hash_blocksize, self.left_hash, self.right_hash
        )
    }
}

struct HashState {
    window: [u8; ROLLING_WINDOW as usize],
    window_sum: Wrapping<u32>,  // h1
    window_sum2: Wrapping<u32>, // h2
    shift_hash: Wrapping<u32>,  // h3
    position: u32,
    left_hash_value: Wrapping<u32>,
    right_hash_value: Wrapping<u32>,
}

#[derive(Copy, Clone, Default)]
pub struct SpamsumOptions {
    pub blocksize: u32,
    pub ignore_whitespace: bool,
    pub ignore_headers: bool,
}

pub fn get_spamsum(input: &Vec<u8>) -> Result<Spamsum, &'static str> {
    let options: SpamsumOptions = Default::default();
    get_configured_spamsum(&input, options)
}

pub fn get_configured_spamsum(
    input: &Vec<u8>,
    options: SpamsumOptions,
) -> Result<Spamsum, &'static str> {
    let mut valid_input: Vec<u8> = input.clone();
    filter_input(&mut valid_input, options);
    let blocksize = if options.blocksize > 0 {
        options.blocksize
    } else {
        guess_initial_blocksize(valid_input.len() as u32)
    };
    let mut result = get_spamsum_with_set_blocksize(&valid_input, blocksize, options).unwrap();
    if options.blocksize == 0 {
        while result.left_hash_blocksize > MIN_BLOCKSIZE
            && result.left_hash.len() - 1 < RIGHT_HASH_LENGTH as usize
        {
            result = get_spamsum_with_set_blocksize(
                &valid_input,
                result.left_hash_blocksize / 2,
                options,
            )
            .unwrap();
        }
    }
    Ok(result)
}

fn filter_input(input: &mut Vec<u8>, options: SpamsumOptions) {
    if options.ignore_headers {
        // find two consecutive newlines indicating the end of email headers
        let two_newlines = input.windows(2).position(|window| window == [0xA, 0xA]);
        let new_start = match two_newlines {
            Some(position) => position + 2,
            _ => 0,
        };
        input.drain(0..new_start);
        input.shrink_to_fit();
    }
    if options.ignore_whitespace {
        // imitating C's isspace(c) (POSIX locale), removing ASCII
        // spaces, tabs, newlines, feeds, carriage returns, _and_ vertical tabs
        let whitespaces = [0x20, 0x9, 0xA, 0xB, 0xC, 0xD];
        input.retain(|&c| !whitespaces.contains(&c));
    }
}

fn get_spamsum_with_set_blocksize(
    input: &Vec<u8>,
    blocksize: u32,
    _options: SpamsumOptions,
) -> Result<Spamsum, &'static str> {
    let mut result = Spamsum {
        left_hash_blocksize: blocksize,
        left_hash: String::with_capacity(LEFT_HASH_LENGTH as usize),
        right_hash: String::with_capacity(RIGHT_HASH_LENGTH as usize),
    };
    let mut rolling_hash: Wrapping<u32> = Wrapping(0);
    let mut hash_state = HashState {
        window: [0; ROLLING_WINDOW as usize],
        window_sum: Wrapping(0),
        window_sum2: Wrapping(0),
        shift_hash: Wrapping(0),
        position: 0,
        left_hash_value: HASH_INIT,
        right_hash_value: HASH_INIT,
    };
    for element in input {
        let c: u32 = *element as u32;
        let rolling_pos = (hash_state.position % ROLLING_WINDOW) as usize;

        hash_state.window_sum2 -= hash_state.window_sum;
        hash_state.window_sum2 += Wrapping(ROLLING_WINDOW * c);

        hash_state.window_sum -= Wrapping(hash_state.window[rolling_pos] as u32);
        hash_state.window_sum += Wrapping(c);

        hash_state.shift_hash <<= 5;
        hash_state.shift_hash ^= Wrapping(c);

        hash_state.window[rolling_pos] = *element;
        hash_state.position += 1;

        hash_state.left_hash_value *= HASH_PRIME;
        hash_state.left_hash_value ^= Wrapping(c);

        hash_state.right_hash_value *= HASH_PRIME;
        hash_state.right_hash_value ^= Wrapping(c);

        rolling_hash = hash_state.window_sum + hash_state.window_sum2 + hash_state.shift_hash;

        // check for reset point of left hash
        if (rolling_hash + Wrapping(1)).0 % result.left_hash_blocksize == 0 {
            update_hash_output(
                &mut hash_state.left_hash_value,
                &mut result.left_hash,
                LEFT_HASH_LENGTH,
            );
        }
        // check for reset point of right hash
        if (rolling_hash + Wrapping(1)).0 % result.right_hash_blocksize() == 0 {
            update_hash_output(
                &mut hash_state.right_hash_value,
                &mut result.right_hash,
                RIGHT_HASH_LENGTH,
            );
        }
    }

    // collect any leftovers so that we have always the last part of the message
    if rolling_hash != Wrapping(0) {
        update_hash_output(
            &mut hash_state.left_hash_value,
            &mut result.left_hash,
            LEFT_HASH_LENGTH,
        );
        update_hash_output(
            &mut hash_state.right_hash_value,
            &mut result.right_hash,
            RIGHT_HASH_LENGTH,
        );
    }
    Ok(result)
}

fn update_hash_output(hash_value: &mut Wrapping<u32>, hash_output: &mut String, hash_length: u32) {
    let output_index: usize = (hash_value.0 % 64) as usize;
    if hash_output.len() == (hash_length as usize) {
        hash_output.pop();
    } else if hash_output.len() < (hash_length - 1) as usize {
        *hash_value = HASH_INIT;
    }
    hash_output.push(BASE64_CHARSET.chars().nth(output_index).unwrap());
}

fn guess_initial_blocksize(input_length: u32) -> u32 {
    let mut blocksize: u32 = MIN_BLOCKSIZE;
    while blocksize * LEFT_HASH_LENGTH < input_length {
        blocksize *= 2;
    }
    blocksize
}

#[cfg(test)]
mod main_tests {
    use super::*;

    #[test]
    fn test_get_left_blocksize() {
        assert_eq!(guess_initial_blocksize(1), 3);
        assert_eq!(guess_initial_blocksize(3 * 64), 3);
        assert_eq!(guess_initial_blocksize(3 * 64 + 1), 6);
        assert_eq!(guess_initial_blocksize(6 * 64 + 1), 12);
    }

    #[test]
    fn test_get_right_blocksize() {
        let spamsum = Spamsum {
            left_hash_blocksize: 6,
            left_hash: String::new(),
            right_hash: String::new(),
        };
        assert_eq!(spamsum.right_hash_blocksize(), 12);
    }

    #[test]
    fn test_filter_whitespaces() {
        let mut input: Vec<u8> = b"H\tE\rLL\n\nO O\n".to_vec();
        let options = SpamsumOptions {
            blocksize: 0,
            ignore_headers: false,
            ignore_whitespace: true,
        };
        filter_input(&mut input, options);
        assert_eq!(input, b"HELLOO".to_vec());
    }

    #[test]
    fn test_filter_email_headers() {
        let mut input: Vec<u8> = b"X-Spam: YES\nX-Score: 1337\n\nDear Sir\n\nPlease buy\n".to_vec();
        let options = SpamsumOptions {
            blocksize: 0,
            ignore_headers: true,
            ignore_whitespace: false,
        };
        filter_input(&mut input, options);
        assert_eq!(input, b"Dear Sir\n\nPlease buy\n".to_vec());
    }

    #[test]
    fn test_filter_email_headers_no_headers() {
        let mut input: Vec<u8> = b"NO HEADER\nTO BE FOUND!\n".to_vec();
        let options = SpamsumOptions {
            blocksize: 0,
            ignore_headers: true,
            ignore_whitespace: false,
        };
        filter_input(&mut input, options);
        assert_eq!(input, b"NO HEADER\nTO BE FOUND!\n".to_vec());
    }

    #[test]
    fn test_filter_both() {
        let mut input: Vec<u8> = b"X-Spam: YES\nX-Score: 1337\n\nDear Sir\n\nPlease buy\n".to_vec();
        let options = SpamsumOptions {
            blocksize: 0,
            ignore_headers: true,
            ignore_whitespace: true,
        };
        filter_input(&mut input, options);
        assert_eq!(input, b"DearSirPleasebuy".to_vec());
    }

    #[test]
    fn test_calculate_spamsum() {
        let expected_spamsum = Spamsum {
            left_hash_blocksize: 3,
            left_hash: String::from("Hn"),
            right_hash: String::from("Hn"),
        };
        let input: Vec<u8> = b"test".to_vec();
        let spamsum = get_spamsum(&input).unwrap();
        assert_eq!(spamsum.to_string(), expected_spamsum.to_string());
    }

    #[test]
    fn test_calculate_another_spamsum() {
        let expected_spamsum = Spamsum {
            left_hash_blocksize: 3,
            left_hash: String::from("clclDDvWIMF/hv"),
            right_hash: String::from("cGZ/EJv"),
        };
        let input: Vec<u8> = b"Please buy my stuff\nDear Sir or Madam\n".to_vec();
        let spamsum = get_spamsum(&input).unwrap();
        assert_eq!(spamsum.to_string(), expected_spamsum.to_string());
    }

    #[test]
    fn test_calculate_spamsum_with_set_blocksize() {
        let expected_spamsum = Spamsum {
            left_hash_blocksize: 11,
            left_hash: String::from("ccsv"),
            right_hash: String::from("Iv"),
        };
        let options = SpamsumOptions {
            blocksize: 11,
            ignore_headers: false,
            ignore_whitespace: false,
        };
        let input: Vec<u8> = b"Please buy my stuff\nDear Sir or Madam\n".to_vec();
        let spamsum = get_configured_spamsum(&input, options).unwrap();
        assert_eq!(spamsum.to_string(), expected_spamsum.to_string());
    }
}
