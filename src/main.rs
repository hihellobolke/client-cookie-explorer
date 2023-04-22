use anyhow::Result;
use clap::Parser;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::prelude::*;
use serde_json::Value;

mod cli;

fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    // read file into string, trim it.
    let jwe_input = fs::read_to_string(cli.input)?;
    let jwe_input = jwe_input.trim();

    // sha256 the secret
    let mut hasher = Sha256::new();
    hasher.update(cli.secret.as_bytes());
    let jwe_password = hasher.finalize();
    let jwe_password = jwe_password.to_vec();

    // jwe decrypt
    let alg = josekit::jwe::alg::direct::DirectJweAlgorithm::Dir;
    let d = alg.decrypter_from_bytes(jwe_password)?;
    let (output, _) = josekit::jwe::deserialize_compact(jwe_input, &d)?;

    // decompress the payload
    let mut z = flate2::read::ZlibDecoder::new(output.as_slice());
    let mut s = String::new();
    z.read_to_string(&mut s).unwrap();
    let s = s.trim_end_matches('\0');

    // parse decompressed string to Json
    let v: Value = serde_json::from_str(s)?;

    // print the result
    println!("-------------------------");
    println!("Input: {:?}", &jwe_input);
    println!("-------------------------");
    println!(
        "size_of_cookie: {}, compressed_payload: {}, decompressed_payload:{}",
        jwe_input.len(),
        z.total_in(),
        z.total_out()
    );
    println!("-------------------------");
    println!("Output: {}", serde_json::to_string_pretty(&v)?);
    println!("-------------------------");

    Ok(())
}
