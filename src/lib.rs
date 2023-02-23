use std::{
    fs::File,
    io::{prelude::*, BufReader},
    path::Path,
    time::SystemTime,
    collections::HashSet,
};
use colored::Colorize;
use rayon::prelude::*;

static MAGIC_STR: &[u8; 20] = b"12345678901234567890";

/// Calculates the hashes for a given cheat string
pub fn calc_hash(cheat_string: String) -> u32 {
    let mut obfuscated_cheat_string: [u8; 20] = *MAGIC_STR;

    let mut cheat_string_crc = !crc32fast::hash(cheat_string.as_bytes()) as i32;
    let mut new_crc: i32;

    let mut buf = itoa::Buffer::new();

    for i in 0..100_000 {
        new_crc = cheat_string_crc + i;

        let new_crc_s = buf.format(new_crc).as_bytes();
        obfuscated_cheat_string[..new_crc_s.len()].copy_from_slice(new_crc_s);
        obfuscated_cheat_string[new_crc_s.len()] = b'x';

        cheat_string_crc = !crc32fast::hash(&obfuscated_cheat_string) as i32;
    }
    let c1 = !crc32fast::hash(&cheat_string.as_bytes()[cheat_string.len() / 3..]);
    let c2 = !crc32fast::hash(&obfuscated_cheat_string);

    c1 ^ c2
}

/// Checks a single candidate cheat code against a list of known cheat hashes
pub fn check_single_cheat(cheat: String, hash_set: &HashSet<u32>) {
    // Calculate checksum for this cheat
    let c = calc_hash(cheat.to_string());

    // Check for matches...
    if hash_set.contains(&c) {
        println!("Found a cheat! {} ({})", cheat.bold().green(), c);
    }
}

fn hex_to_u32(s: &str) -> u32 {
    let s = s.strip_prefix('0').unwrap_or(s);
    let s = s.strip_prefix(['x', 'X']).unwrap_or(s);

    u32::from_str_radix(s, 16).unwrap_or(0)
}

/// Hashes a list of candidate cheat codes and checks them against a list of known cheat hashes
pub fn crack_hashes(cheat_list: &String, hash_list: &String) {
    println!("Cheat List: {cheat_list}");
    println!("Hash List: {hash_list}");

    // Build up hash set
    let hash_list_entries = lines_from_file(hash_list);
    let mut hash_set = HashSet::new();
    for hash_line in hash_list_entries {
        let (a_s, b_s) = hash_line.split_once(',').expect("Hash list malformed!");
        let (a, b) = (hex_to_u32(a_s), hex_to_u32(b_s));
        hash_set.insert(a ^ b);
    }

    // Load candidate cheats
    let candidate_cheats = lines_from_file(cheat_list);

    // Establish global thread pool
    let num_cores: usize = std::thread::available_parallelism().unwrap().get();
    rayon::ThreadPoolBuilder::new().num_threads(num_cores).build_global().unwrap();

    println!("Starting to crack using {num_cores} cores");
    
    let now = SystemTime::now();
    candidate_cheats.par_iter().for_each(|cheat| {
        check_single_cheat(cheat.to_string(), &hash_set);
    });

    // Print time info
    let elapsed_ms = now.elapsed().unwrap().as_millis();
    let time_per_thousand = elapsed_ms as f64 / candidate_cheats.len() as f64;
    println!("Took {:.4} seconds (That's {:.4} seconds per 1,000 hashes)", elapsed_ms as f64 / 1000.0, time_per_thousand);
}

/// Reads a file into a list of lines
/// 
/// Taken from https://stackoverflow.com/a/35820003
pub fn lines_from_file(filename: impl AsRef<Path>) -> Vec<String> {
    let file = File::open(filename).expect("no such file");
    let buf = BufReader::new(file);
    buf.lines()
        .map(|l| l.expect("Could not parse line"))
        .collect()
}