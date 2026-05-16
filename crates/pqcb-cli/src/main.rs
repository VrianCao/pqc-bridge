#![deny(missing_debug_implementations)]
//! PQC Bridge command-line interface.

use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use pqcb_core::algorithms::{HybridKemAlgorithm, KemAlgorithm, SignatureAlgorithm};
use pqcb_core::version::{ABI_VERSION, PACKAGE_NAME, PROJECT_NAME, VERSION};

#[derive(Debug, Parser)]
#[command(name = PACKAGE_NAME)]
#[command(version = VERSION)]
#[command(about = "Developer-friendly post-quantum cryptography tools.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print PQC Bridge version information.
    Version,
    /// List algorithms planned for the v0.1 SDK surface.
    Algorithms,
    /// Generate a key pair.
    Keygen {
        /// Algorithm family.
        #[arg(long, value_enum)]
        kind: KeyKind,
        /// Algorithm name.
        #[arg(long)]
        algorithm: String,
    },
    /// Seal a message for a recipient.
    Seal,
    /// Open a sealed message.
    Open,
    /// Sign a message.
    Sign,
    /// Verify a message signature.
    Verify,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum KeyKind {
    /// Key encapsulation mechanism key pair.
    Kem,
    /// Digital signature key pair.
    Signature,
    /// Hybrid KEM profile key pair.
    Hybrid,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Version => {
            println!("{PROJECT_NAME} {VERSION}");
            println!("package: {PACKAGE_NAME}");
            println!("abi: {ABI_VERSION}");
        }
        Command::Algorithms => {
            println!("KEM:");
            println!("  - {}", KemAlgorithm::MlKem768);
            println!("Signature:");
            println!("  - {}", SignatureAlgorithm::MlDsa65);
            println!("Hybrid:");
            println!("  - {}", HybridKemAlgorithm::X25519MlKem768);
        }
        Command::Keygen { kind, algorithm } => {
            validate_key_algorithm(kind, &algorithm)?;
            bail!("key generation backend is not configured in v0.1 scaffold")
        }
        Command::Seal | Command::Open | Command::Sign | Command::Verify => {
            bail!("cryptographic backend is not configured in v0.1 scaffold")
        }
    }

    Ok(())
}

fn validate_key_algorithm(kind: KeyKind, algorithm: &str) -> Result<()> {
    match kind {
        KeyKind::Kem => {
            let _ = algorithm.parse::<KemAlgorithm>()?;
        }
        KeyKind::Signature => {
            let _ = algorithm.parse::<SignatureAlgorithm>()?;
        }
        KeyKind::Hybrid => {
            let _ = algorithm.parse::<HybridKemAlgorithm>()?;
        }
    }

    Ok(())
}
