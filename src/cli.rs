use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Sets a file for reading cookie to be decrypted
    #[arg(long, value_name = "FILE")]
    pub input: PathBuf,

    /// Set secret for decrypting file
    #[arg(short, long, value_name = "SECRET")]
    pub secret: String,
}
