#![deny(missing_debug_implementations)]
//! PQC Bridge command-line interface.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use pqcb_backend_rustcrypto::{kem, signature};
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
        /// Path to write public key bytes.
        #[arg(long)]
        public_out: PathBuf,
        /// Path to write secret key bytes.
        #[arg(long)]
        secret_out: PathBuf,
    },
    /// Encapsulate a shared secret to a KEM public key.
    Encapsulate {
        /// KEM algorithm name.
        #[arg(long)]
        algorithm: String,
        /// Path to raw public key bytes.
        #[arg(long)]
        public_key: PathBuf,
        /// Path to write ciphertext bytes.
        #[arg(long)]
        ciphertext_out: PathBuf,
        /// Path to write shared secret bytes.
        #[arg(long)]
        shared_secret_out: PathBuf,
    },
    /// Decapsulate a shared secret from a KEM ciphertext.
    Decapsulate {
        /// KEM algorithm name.
        #[arg(long)]
        algorithm: String,
        /// Path to raw secret key bytes.
        #[arg(long)]
        secret_key: PathBuf,
        /// Path to raw ciphertext bytes.
        #[arg(long)]
        ciphertext: PathBuf,
        /// Path to write shared secret bytes.
        #[arg(long)]
        shared_secret_out: PathBuf,
    },
    /// Seal a message for a recipient.
    Seal,
    /// Open a sealed message.
    Open,
    /// Sign a message.
    Sign {
        /// Signature algorithm name.
        #[arg(long)]
        algorithm: String,
        /// Path to raw secret key bytes.
        #[arg(long)]
        secret_key: PathBuf,
        /// Path to message bytes.
        #[arg(long)]
        message: PathBuf,
        /// Path to write signature bytes.
        #[arg(long)]
        signature_out: PathBuf,
    },
    /// Verify a message signature.
    Verify {
        /// Signature algorithm name.
        #[arg(long)]
        algorithm: String,
        /// Path to raw public key bytes.
        #[arg(long)]
        public_key: PathBuf,
        /// Path to message bytes.
        #[arg(long)]
        message: PathBuf,
        /// Path to raw signature bytes.
        #[arg(long)]
        signature: PathBuf,
    },
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
        Command::Keygen {
            kind,
            algorithm,
            public_out,
            secret_out,
        } => {
            run_keygen(kind, &algorithm, &public_out, &secret_out)?;
        }
        Command::Encapsulate {
            algorithm,
            public_key,
            ciphertext_out,
            shared_secret_out,
        } => {
            run_encapsulate(&algorithm, &public_key, &ciphertext_out, &shared_secret_out)?;
        }
        Command::Decapsulate {
            algorithm,
            secret_key,
            ciphertext,
            shared_secret_out,
        } => {
            run_decapsulate(&algorithm, &secret_key, &ciphertext, &shared_secret_out)?;
        }
        Command::Sign {
            algorithm,
            secret_key,
            message,
            signature_out,
        } => {
            run_sign(&algorithm, &secret_key, &message, &signature_out)?;
        }
        Command::Verify {
            algorithm,
            public_key,
            message,
            signature,
        } => {
            run_verify(&algorithm, &public_key, &message, &signature)?;
        }
        Command::Seal | Command::Open => {
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

fn run_keygen(kind: KeyKind, algorithm: &str, public_out: &Path, secret_out: &Path) -> Result<()> {
    validate_key_algorithm(kind, algorithm)?;
    match kind {
        KeyKind::Kem => {
            let algorithm = algorithm.parse::<KemAlgorithm>()?;
            if algorithm != KemAlgorithm::MlKem768 {
                bail!("unsupported KEM algorithm: {algorithm}");
            }
            let keypair = kem::keypair()?;
            write_file(public_out, keypair.public_key.as_bytes())?;
            write_file(secret_out, keypair.secret_key.expose_secret())?;
            println!("wrote public key: {}", public_out.display());
            println!("wrote secret key: {}", secret_out.display());
        }
        KeyKind::Signature => {
            let algorithm = algorithm.parse::<SignatureAlgorithm>()?;
            if algorithm != SignatureAlgorithm::MlDsa65 {
                bail!("unsupported signature algorithm: {algorithm}");
            }
            let keypair = signature::keypair()?;
            write_file(public_out, keypair.public_key.as_bytes())?;
            write_file(secret_out, keypair.secret_key.expose_secret())?;
            println!("wrote public key: {}", public_out.display());
            println!("wrote secret key: {}", secret_out.display());
        }
        KeyKind::Hybrid => bail!("hybrid key generation is not implemented"),
    }

    Ok(())
}

fn run_encapsulate(
    algorithm: &str,
    public_key: &Path,
    ciphertext_out: &Path,
    shared_secret_out: &Path,
) -> Result<()> {
    let algorithm = algorithm.parse::<KemAlgorithm>()?;
    if algorithm != KemAlgorithm::MlKem768 {
        bail!("unsupported KEM algorithm: {algorithm}");
    }

    let public_key = kem::public_key(read_file(public_key)?);
    let encapsulation = kem::encapsulate(&public_key)?;
    write_file(ciphertext_out, encapsulation.ciphertext())?;
    write_file(shared_secret_out, encapsulation.expose_shared_secret())?;
    println!("wrote ciphertext: {}", ciphertext_out.display());
    println!("wrote shared secret: {}", shared_secret_out.display());

    Ok(())
}

fn run_decapsulate(
    algorithm: &str,
    secret_key: &Path,
    ciphertext: &Path,
    shared_secret_out: &Path,
) -> Result<()> {
    let algorithm = algorithm.parse::<KemAlgorithm>()?;
    if algorithm != KemAlgorithm::MlKem768 {
        bail!("unsupported KEM algorithm: {algorithm}");
    }

    let secret_key = kem::secret_key(read_file(secret_key)?);
    let ciphertext = read_file(ciphertext)?;
    let shared_secret = kem::decapsulate(&secret_key, &ciphertext)?;
    write_file(shared_secret_out, shared_secret.as_slice())?;
    println!("wrote shared secret: {}", shared_secret_out.display());

    Ok(())
}

fn run_sign(
    algorithm: &str,
    secret_key: &Path,
    message: &Path,
    signature_out: &Path,
) -> Result<()> {
    let algorithm = algorithm.parse::<SignatureAlgorithm>()?;
    if algorithm != SignatureAlgorithm::MlDsa65 {
        bail!("unsupported signature algorithm: {algorithm}");
    }

    let secret_key = signature::secret_key(read_file(secret_key)?);
    let message = read_file(message)?;
    let signature_bytes = signature::sign(&secret_key, &message)?;
    write_file(signature_out, &signature_bytes)?;
    println!("wrote signature: {}", signature_out.display());

    Ok(())
}

fn run_verify(
    algorithm: &str,
    public_key: &Path,
    message: &Path,
    signature_path: &Path,
) -> Result<()> {
    let algorithm = algorithm.parse::<SignatureAlgorithm>()?;
    if algorithm != SignatureAlgorithm::MlDsa65 {
        bail!("unsupported signature algorithm: {algorithm}");
    }

    let public_key = signature::public_key(read_file(public_key)?);
    let message = read_file(message)?;
    let signature_bytes = read_file(signature_path)?;
    signature::verify(&public_key, &message, &signature_bytes)?;
    println!("signature valid");

    Ok(())
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("read {}", path.display()))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn ml_kem_cli_smoke_round_trip() {
        let dir = temp_dir();
        fs::create_dir_all(&dir).expect("create temp dir");

        let public_key = dir.join("kem.pub");
        let secret_key = dir.join("kem.sec");
        let ciphertext = dir.join("kem.ct");
        let encapsulated_secret = dir.join("kem.ss.enc");
        let decapsulated_secret = dir.join("kem.ss.dec");

        run_keygen(KeyKind::Kem, "ML-KEM-768", &public_key, &secret_key).expect("keygen");
        run_encapsulate("ML-KEM-768", &public_key, &ciphertext, &encapsulated_secret)
            .expect("encapsulate");
        run_decapsulate("ML-KEM-768", &secret_key, &ciphertext, &decapsulated_secret)
            .expect("decapsulate");

        assert_eq!(
            fs::read(encapsulated_secret).expect("read encapsulated secret"),
            fs::read(decapsulated_secret).expect("read decapsulated secret")
        );
    }

    #[test]
    fn ml_dsa_cli_smoke_sign_verify_and_tamper() {
        let dir = temp_dir();
        fs::create_dir_all(&dir).expect("create temp dir");

        let public_key = dir.join("dsa.pub");
        let secret_key = dir.join("dsa.sec");
        let message = dir.join("message.txt");
        let tampered = dir.join("tampered.txt");
        let signature = dir.join("message.sig");

        fs::write(&message, b"message").expect("write message");
        fs::write(&tampered, b"tampered").expect("write tampered message");

        run_keygen(KeyKind::Signature, "ML-DSA-65", &public_key, &secret_key).expect("keygen");
        run_sign("ML-DSA-65", &secret_key, &message, &signature).expect("sign");
        run_verify("ML-DSA-65", &public_key, &message, &signature).expect("verify");

        assert!(run_verify("ML-DSA-65", &public_key, &tampered, &signature).is_err());
    }

    fn temp_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("pqcb-cli-test-{nonce}"))
    }
}
