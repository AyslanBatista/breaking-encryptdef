# Breaking Encryptdef

Breaking Encryptdef é uma ferramenta em Rust para realizar brute-force em mensagens criptografadas com AES-GCM, onde a chave é derivada usando scrypt. O objetivo é descobrir, por tentativa e erro, qual é a senha correta utilizada na encriptação.

A mensagem criptografada deve ser composta por **4 partes** separadas por asteriscos (`*`), onde cada parte é codificada em Base64. Essas partes correspondem, na ordem original, a um conjunto de dados necessários para a decriptação, mas **a ordem pode variar**. Assim, a ferramenta testa todas as 24 permutações possíveis para determinar quais partes representam, respectivamente, o _salt_, o _nonce_, o _ciphertext_ e a _tag_.

## Lógica e Funcionamento

### 1. Entrada e Decodificação

- **Entrada:**  
  O programa recebe como entrada:
  - Uma string criptografada no formato:  
    `parte1*parte2*parte3*parte4`
  - Um arquivo _wordlist_ contendo senhas (uma por linha).

- **Divisão e Decodificação:**  
  A string é dividida em 4 partes utilizando o caractere `*` como delimitador. Em seguida, cada parte é decodificada de Base64 para recuperar os dados binários.

### 2. Análise e Pré-processamento

- **Entropia:**  
  Para auxiliar na análise, o programa calcula a entropia (uma medida de aleatoriedade) de cada parte. Partes com entropia mais alta podem indicar dados mais "aleatórios" (por exemplo, o ciphertext ou o tag).

- **Pré-computação das Permutações:**  
  São definidas as 24 combinações possíveis de atribuição dos 4 papéis:
  - **Salt:** Valor usado para derivar a chave.
  - **Nonce:** Número único utilizado na decriptação (pode ter diferentes tamanhos – 16 bytes ou, se tiver pelo menos 12 bytes, usa os 12 primeiros; se menor, é preenchido com zeros à esquerda).
  - **Ciphertext:** O texto cifrado.
  - **Tag:** A autenticação (deve ter exatamente 16 bytes).

### 3. Derivação da Chave e Decriptação

- **Derivação da Chave com scrypt:**  
  Para cada tentativa, a chave é derivada a partir da senha candidata e do salt usando a função scrypt com os parâmetros:
  - `log_n = 14` (equivalente a n = 2^14)
  - `r = 8`
  - `p = 1`
  - `dklen = 32` bytes

- **Tratamento do Nonce:**  
  O algoritmo trata o nonce de acordo com seu tamanho:
  - Se o nonce tiver **16 bytes**, utiliza-se uma variante do AES-GCM que aceita nonces de 16 bytes.
  - Se tiver pelo menos **12 bytes** (mas não 16), são utilizados os 12 primeiros bytes.
  - Se tiver **menos que 12 bytes**, o valor é preenchido (com zeros à esquerda) até atingir 12 bytes.

- **Tentativa de Decriptação:**  
  Para cada senha da wordlist, o programa itera por todas as 24 permutações, derivando a chave e tentando decriptar o ciphertext. Se a decriptação for bem-sucedida, significa que a combinação de:
  - Senha,
  - Salt,
  - Nonce,
  - Ciphertext e
  - Tag  
  está correta.

### 4. Paralelização e Performance

- **Uso do Rayon:**  
  Para acelerar a busca, o projeto utiliza a biblioteca [Rayon](https://github.com/rayon-rs/rayon), que permite a paralelização das iterações sobre a wordlist. Dessa forma, múltiplas senhas são testadas em paralelo, maximizando o uso dos núcleos da CPU.

> **Nota:**  
> A função scrypt é intencionalmente lenta para dificultar ataques de brute-force. Para obter o máximo de desempenho, compile o projeto em _release_:
> 
> ```bash
> cargo run --release -- -s "sua_string_criptografada" -w "wordlist.txt" -v
> ```

### 5. Logs e Saída

No modo verboso (`-v`), o programa exibe mensagens detalhadas de cada tentativa, informando:
- Qual senha está sendo testada.
- A permutação atual (qual parte está sendo considerada como salt, nonce, ciphertext e tag).
- O tamanho do nonce candidato.
- O número da tentativa.

Assim que a senha correta for encontrada, o programa exibe a senha e a combinação correta, e encerra imediatamente sem continuar as demais tentativas.

## Exemplos de Uso

### Exemplo 1: Execução com Verbosidade

```bash
cargo run --release -- -s "pOVQTU7dBmA=*ePEtywX8EKMRlWM/qQpYpA==*upJUFSC1BIiKU32gkAX/GQ==*XW0L3X6W9qISjTfYf+zspQ==" -w "wordlist.txt" -v
```
