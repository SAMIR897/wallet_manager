use aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ethers::signers::{coins_bip39::{English, Mnemonic}, MnemonicBuilder, Signer};
use rand::{thread_rng, RngCore};
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
struct EncryptedStore {
    ciphertext: String,
    nonce: String,
    salt: String,
}

fn get_wallet_path() -> PathBuf {
    let mut path = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    path.push("encrypted_wallet.json");
    path
}

fn derive_key(password: &str, salt: &[u8]) -> Key<Aes256Gcm> {
    let mut input = password.as_bytes().to_vec();
    input.extend_from_slice(salt);
    let hash = ethers::core::utils::keccak256(&input);
    *Key::<Aes256Gcm>::from_slice(&hash)
}

fn create_wallet() {
    let mut rng = thread_rng();
    
    println!("Generating new wallet...");
    let mnemonic = Mnemonic::<English>::new(&mut rng);
    let phrase = mnemonic.to_phrase();
    
    println!("Mnemonic phrase: {}", phrase);
    println!("Please store this phrase securely!\n");

    let wallet = MnemonicBuilder::<English>::default()
        .phrase(phrase.as_str())
        .build()
        .expect("Failed to build wallet");
        
    println!("Wallet successfully generated!");
    println!("Derived Address: {:?}", wallet.address());

    print!("Enter a strong password to encrypt the keystore: ");
    io::stdout().flush().unwrap();
    let password = read_password().unwrap();

    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);

    let key = derive_key(&password, &salt);
    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, phrase.as_bytes())
        .expect("Encryption failed");

    let store = EncryptedStore {
        ciphertext: hex::encode(ciphertext),
        nonce: hex::encode(nonce_bytes),
        salt: hex::encode(salt),
    };

    let path = get_wallet_path();
    let json = serde_json::to_string_pretty(&store).unwrap();
    fs::write(&path, json).expect("Failed to write to file");
    println!("Wallet encrypted and saved to {:?}", path);
}

fn load_wallet() {
    let path = get_wallet_path();
    if !path.exists() {
        println!("No wallet found at {:?}", path);
        return;
    }

    let json = fs::read_to_string(&path).expect("Failed to read file");
    let store: EncryptedStore = serde_json::from_str(&json).expect("Invalid JSON format");

    print!("Enter password to decrypt wallet: ");
    io::stdout().flush().unwrap();
    let password = read_password().unwrap();

    let salt = hex::decode(store.salt).expect("Invalid hex");
    let nonce_bytes = hex::decode(store.nonce).expect("Invalid hex");
    let ciphertext = hex::decode(store.ciphertext).expect("Invalid hex");

    let key = derive_key(&password, &salt);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(plaintext) => {
            let phrase = String::from_utf8(plaintext).expect("Invalid UTF-8");
            let wallet = MnemonicBuilder::<English>::default()
                .phrase(phrase.as_str())
                .build()
                .expect("Failed to build wallet");
            println!("Successfully decrypted wallet!");
            println!("Address: {:?}", wallet.address());
            println!("Mnemonic: {}", phrase);
        }
        Err(_) => {
            println!("Decryption failed. Incorrect password?");
        }
    }
}

fn main() {
    println!("Wallet Manager");
    println!("1. Create new wallet");
    println!("2. Load existing wallet");
    print!("Choose an option: ");
    io::stdout().flush().unwrap();

    let mut choice = String::new();
    io::stdin().read_line(&mut choice).unwrap();

    match choice.trim() {
        "1" => create_wallet(),
        "2" => load_wallet(),
        _ => println!("Invalid choice"),
    }
}
