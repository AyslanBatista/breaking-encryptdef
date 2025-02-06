use aes_gcm::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    AesGcm,
};
use aes::Aes256; // Necessário para a variante que utiliza nonce de 16 bytes
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Arg, Command};
use rayon::prelude::*; // Biblioteca para paralelização
use scrypt::{scrypt, Params};
use std::{
    fs::File,
    io::{self, BufRead},
    path::Path,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Instant,
};

fn main() {
    // ===== PARSING DOS ARGUMENTOS =====
    let matches = Command::new("Breaking Encryptdef")
        .version("1.0")
        .author("Ayslan")
        .about("Brute-force decriptação usando wordlist (paralelizado com Rayon)")
        .arg(
            Arg::new("string")
                .short('s')
                .long("string")
                .value_name("STRING")
                .help("String criptografada (Base64, separada por '*')")
                .required(true),
        )
        .arg(
            Arg::new("wordlist")
                .short('w')
                .long("wordlist")
                .value_name("WORDLIST")
                .help("Caminho para a wordlist")
                .required(true),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Exibe todas as tentativas (modo verboso)")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let verbose = *matches.get_one::<bool>("verbose").unwrap_or(&false);
    let encrypted_string = matches.get_one::<String>("string").unwrap();
    let wordlist_path = matches.get_one::<String>("wordlist").unwrap();

    println!("\n🔒 String criptografada: {}", encrypted_string);
    println!("📂 Wordlist: {}", wordlist_path);

    // ===== DIVISÃO E DECODIFICAÇÃO =====
    println!("\n=== Dividindo a string criptografada ===");
    let encrypted_parts: Vec<&str> = encrypted_string.split('*').collect();
    if encrypted_parts.len() != 4 {
        eprintln!("Erro: A string criptografada deve conter exatamente 4 partes separadas por '*'.");
        return;
    }
    println!("Partes: {:?}", encrypted_parts);

    println!("\n=== Decodificando as partes (Base64) ===");
    let decoded_parts: Vec<Vec<u8>> = match encrypted_parts
        .iter()
        .map(|part| STANDARD.decode(part))
        .collect::<Result<Vec<Vec<u8>>, _>>()
    {
        Ok(parts) => parts,
        Err(err) => {
            eprintln!("Erro ao decodificar Base64: {}", err);
            return;
        }
    };
    println!("Decodificação realizada com sucesso!");

    // Exibe a entropia de cada parte para auxiliar na análise
    println!("\n=== Entropia das Partes ===");
    for (i, part) in decoded_parts.iter().enumerate() {
        println!("Parte {}: Entropia = {:.4}", i + 1, calculate_shannon_entropy(part));
    }

    // ===== LEITURA DA WORDLIST =====
    let passwords = match read_wordlist(wordlist_path) {
        Ok(lista) => lista,
        Err(err) => {
            eprintln!("Erro ao ler a wordlist: {}", err);
            return;
        }
    };
    println!("\n=== Iniciando brute-force com {} senhas ===", passwords.len());

    // ===== PRÉ-COMPUTAÇÃO DAS 24 PERMUTAÇÕES =====
    // Cada tupla representa a atribuição dos papéis (salt, nonce, ciphertext, tag).
    // Por exemplo, (1, 2, 0, 3) significa:
    //   - Salt: Parte 2
    //   - Nonce: Parte 3
    //   - Ciphertext: Parte 1
    //   - Tag: Parte 4
    let permutations: Vec<(usize, usize, usize, usize)> = vec![
        (0, 1, 2, 3),
        (0, 1, 3, 2),
        (0, 2, 1, 3),
        (0, 2, 3, 1),
        (0, 3, 1, 2),
        (0, 3, 2, 1),
        (1, 0, 2, 3),
        (1, 0, 3, 2),
        (1, 2, 0, 3),
        (1, 2, 3, 0),
        (1, 3, 0, 2),
        (1, 3, 2, 0),
        (2, 0, 1, 3),
        (2, 0, 3, 1),
        (2, 1, 0, 3),
        (2, 1, 3, 0),
        (2, 3, 0, 1),
        (2, 3, 1, 0),
        (3, 0, 1, 2),
        (3, 0, 2, 1),
        (3, 1, 0, 2),
        (3, 1, 2, 0),
        (3, 2, 0, 1),
        (3, 2, 1, 0),
    ];

    // ===== CONTADORES ATÔMICOS E FLAG DE SOLUÇÃO =====
    let total_attempts = AtomicUsize::new(0);
    let solution_found = AtomicBool::new(false);
    let start_time = Instant::now();

    // ===== BRUTE-FORCE PARALELO COM RAYON =====
    // Itera em paralelo sobre as senhas da wordlist. Para cada senha, testa todas as 24 permutações.
    // Assim que uma tentativa de decriptação for bem-sucedida, a flag 'solution_found' é ativada e a busca é interrompida.
    let result = passwords
        .par_iter()
        .enumerate()
        .find_map_any(|(pwd_index, password)| {
            if solution_found.load(Ordering::Relaxed) {
                return None;
            }
            // Para cada senha, itera sobre todas as permutações
            for &(salt_idx, nonce_idx, ciphertext_idx, tag_idx) in &permutations {
                if solution_found.load(Ordering::Relaxed) {
                    break;
                }
                // Verifica se a parte candidata para a tag possui exatamente 16 bytes.
                if decoded_parts[tag_idx].len() != 16 {
                    continue;
                }
                total_attempts.fetch_add(1, Ordering::Relaxed);
                println!(
                    "[Senha {}: '{}'] Tentativa {}: Salt=P{}, Nonce=P{} ({} bytes), Ciphertext=P{}, Tag=P{}",
                    pwd_index + 1,
                    password,
                    total_attempts.load(Ordering::Relaxed),
                    salt_idx + 1,
                    nonce_idx + 1,
                    decoded_parts[nonce_idx].len(),
                    ciphertext_idx + 1,
                    tag_idx + 1,
                );
                if try_decrypt_with_assignment(
                    &decoded_parts,
                    password,
                    salt_idx,
                    nonce_idx,
                    ciphertext_idx,
                    tag_idx,
                    verbose,
                ) {
                    solution_found.store(true, Ordering::Relaxed);
                    return Some((pwd_index, password.clone(), (salt_idx, nonce_idx, ciphertext_idx, tag_idx)));
                }
            }
            None
        });

    let duration = start_time.elapsed();
    let attempts = total_attempts.load(Ordering::Relaxed);
    if let Some((pwd_index, password, (salt_idx, nonce_idx, ciphertext_idx, tag_idx))) = result {
        println!("\n🔥 Senha encontrada!");
        println!("    [Senha {}: '{}']", pwd_index + 1, password);
        println!("    Atribuição correta:");
        println!("         Salt: Parte {}", salt_idx + 1);
        println!(
            "         Nonce: Parte {} ({} bytes)",
            nonce_idx + 1,
            decoded_parts[nonce_idx].len()
        );
        println!("         Ciphertext: Parte {}", ciphertext_idx + 1);
        println!("         Tag: Parte {}", tag_idx + 1);
        println!("Total de tentativas: {} em {:.2?}", attempts, duration);
    } else {
        println!(
            "\nNenhuma senha válida encontrada após {} tentativas em {:.2?}.",
            attempts, duration
        );
    }
}

/// Calcula a entropia de Shannon para uma fatia de bytes.
/// (A entropia mede a aleatoriedade dos dados.)
fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    let mut freq = std::collections::HashMap::new();
    for &byte in data {
        *freq.entry(byte).or_insert(0) += 1;
    }
    let len = data.len() as f64;
    freq.values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Lê uma wordlist de um arquivo e retorna um vetor com as senhas.
fn read_wordlist(filename: &str) -> io::Result<Vec<String>> {
    let path = Path::new(filename);
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let passwords = reader.lines().filter_map(|linha| linha.ok()).collect();
    Ok(passwords)
}

/// Tenta a decriptação utilizando a atribuição dos papéis fornecida:
/// - Deriva a chave utilizando scrypt com os parâmetros: log_n=14, r=8, p=1, dklen=32.
/// - Dependendo do tamanho do candidato para nonce:
///    • Se tiver 16 bytes, utiliza uma variante do AES-GCM que aceita nonce de 16 bytes.
///    • Se tiver pelo menos 12 bytes (mas não 16), utiliza os 12 primeiros bytes.
///    • Se tiver menos que 12 bytes, preenche com zeros à esquerda até atingir 12 bytes.
/// Retorna verdadeiro se a decriptação for bem-sucedida. Em caso de sucesso, tenta converter o resultado para texto legível.
fn try_decrypt_with_assignment(
    parts: &Vec<Vec<u8>>,
    password: &str,
    salt_idx: usize,
    nonce_idx: usize,
    ciphertext_idx: usize,
    tag_idx: usize,
    verbose: bool,
) -> bool {
    let salt = &parts[salt_idx];
    let nonce_candidate = &parts[nonce_idx];
    let ciphertext = &parts[ciphertext_idx];
    let tag = &parts[tag_idx];

    // Deriva a chave utilizando scrypt (parâmetros compatíveis com o Python)
    let mut key = vec![0u8; 32];
    let params = Params::new(14, 8, 1).unwrap();
    if scrypt(password.as_bytes(), salt, &params, &mut key).is_err() {
         return false;
    }

    // Concatena ciphertext e tag (o AES-GCM espera o tag anexado ao ciphertext)
    let mut combined = ciphertext.clone();
    combined.extend_from_slice(tag);

    // Caso 1: Nonce com 16 bytes – utiliza variante do AES-GCM que aceita nonce de 16 bytes.
    if nonce_candidate.len() == 16 {
         use aes_gcm::aead::consts::U16;
         type Aes256Gcm16 = AesGcm<Aes256, U16>;
         let key_ga = GenericArray::from_slice(&key);
         let cipher = Aes256Gcm16::new(key_ga);
         let nonce_ga = GenericArray::from_slice(nonce_candidate);
         match cipher.decrypt(nonce_ga, combined.as_ref()) {
              Ok(plaintext) => {
                  if verbose {
                      match std::str::from_utf8(&plaintext) {
                          Ok(texto) => println!("Decriptação bem-sucedida. Texto: {}", texto),
                          Err(_) => println!("Decriptação bem-sucedida. Dados (bytes): {:?}", plaintext),
                      }
                  }
                  return true;
              },
              Err(_) => return false,
         }
    }
    // Caso 2: Nonce com pelo menos 12 bytes (mas não 16) – utiliza os 12 primeiros bytes.
    else if nonce_candidate.len() >= 12 {
         use aes_gcm::Aes256Gcm;
         let key_ga = GenericArray::from_slice(&key);
         let cipher = Aes256Gcm::new(key_ga);
         let nonce_ga = GenericArray::from_slice(&nonce_candidate[..12]);
         match cipher.decrypt(nonce_ga, combined.as_ref()) {
              Ok(plaintext) => {
                  if verbose {
                      match std::str::from_utf8(&plaintext) {
                          Ok(texto) => println!("Decriptação bem-sucedida. Texto: {}", texto),
                          Err(_) => println!("Decriptação bem-sucedida. Dados (bytes): {:?}", plaintext),
                      }
                  }
                  return true;
              },
              Err(_) => return false,
         }
    }
    // Caso 3: Nonce com menos que 12 bytes – preenche com zeros à esquerda até atingir 12 bytes.
    else {
         let mut padded = vec![0u8; 12];
         padded[12 - nonce_candidate.len()..].copy_from_slice(nonce_candidate);
         use aes_gcm::Aes256Gcm;
         let key_ga = GenericArray::from_slice(&key);
         let cipher = Aes256Gcm::new(key_ga);
         let nonce_ga = GenericArray::from_slice(&padded);
         match cipher.decrypt(nonce_ga, combined.as_ref()) {
              Ok(plaintext) => {
                  if verbose {
                      match std::str::from_utf8(&plaintext) {
                          Ok(texto) => println!("Decriptação bem-sucedida. Texto: {}", texto),
                          Err(_) => println!("Decriptação bem-sucedida. Dados (bytes): {:?}", plaintext),
                      }
                  }
                  return true;
              },
              Err(_) => return false,
         }
    }
}
