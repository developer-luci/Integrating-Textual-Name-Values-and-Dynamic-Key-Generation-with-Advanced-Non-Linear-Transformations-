# Integrating Textual Name Values and Dynamic Key Generation with Advanced Non-Linear Transformations for Encryption

## Abstract
This project presents a novel cryptographic framework that integrates textual name values and dynamic key generation with advanced non-linear transformations to enhance encryption security. The system employs lattice-based key generation using the Number Theoretic Transform (NTT), dynamic AES S-box generation, character-to-name mapping for data obfuscation, and SHA-256 hashing for message integrity verification. This hybrid approach offers improved resistance against brute-force and differential cryptanalytic attacks.

## Keywords
- AES encryption  
- Dynamic S-box  
- Lattice-based cryptography  
- Number Theoretic Transform (NTT)  
- SHA-256  
- Textual Name Mapping  
- Post-quantum cryptography  

## Table of Contents
1. [Introduction](#introduction)
2. [Problem Statement & Objectives](#problem-statement--objectives)
3. [Existing System](#existing-system)
4. [Proposed System](#proposed-system)
5. [System Architecture](#system-architecture)
6. [Results & Discussion](#results--discussion)
7. [Conclusion](#conclusion)
8. [Installation](#installation)
9. [Usage](#usage)
10. [References](#references)
11. [Authors](#authors)
12. [License](#license)
13. [Acknowledgements](#acknowledgements)

## Introduction
In today’s digital era, securing sensitive data is critical. Traditional encryption methods often rely on static keys and fixed transformation algorithms that can be vulnerable to attacks. This project addresses these shortcomings by introducing a dynamic, robust encryption framework that integrates advanced cryptographic techniques to achieve both security and efficiency.

## Problem Statement & Objectives
Conventional encryption systems are limited by:
- **Static Key Generation:** Predictable keys make systems vulnerable to brute-force attacks.
- **Fixed S-boxes in AES:** Lack of adaptability leads to susceptibility against known-plaintext and differential attacks.

The objectives of this project are:
- To integrate textual name values for enhanced key randomness.
- To develop dynamic key generation using lattice-based cryptography and NTT.
- To generate dynamic AES S-boxes for each encryption session.
- To ensure data integrity through SHA-256 hashing.

## Existing System
Existing systems such as traditional AES and public key infrastructures use static keys and fixed S-boxes, which can expose encrypted data to various cryptanalytic attacks. This project seeks to overcome these limitations by introducing dynamic and adaptive techniques.

## Proposed System
The proposed cryptographic framework comprises:
- **Lattice-Based Key Generation:** Utilizes NTT and its inverse (INTT) for efficient, session-specific key generation.
- **Dynamic AES S-box Generation:** Generates a unique S-box for every encryption session, increasing resistance to attacks.
- **Character-to-Name Mapping:** Obfuscates plaintext data before encryption.
- **SHA-256 Hashing:** Ensures message integrity by appending a secure hash to the ciphertext.

## System Architecture
The system is structured around the following key components:
- **Lattice-Based Key Generation:** Enhances security by creating non-linear, unpredictable keys.
- **AES Encryption with Dynamic S-box:** Utilizes a dynamically generated S-box derived from the AES key.
- **Character-to-Name Transformations:** Provides additional data obfuscation.
- **SHA-256 Integrity Check:** Verifies data authenticity by detecting any tampering.

For a detailed architectural description, please refer to the [project paper](./IJIRT169305_PAPER.pdf).

## Results & Discussion
The system has been rigorously tested with:
- **Avalanche Effect Testing:** An average bit change of 51.72% was observed when a single bit in the input was modified.
- **Statistical Randomness:** Key tests (frequency and runs) confirmed statistically significant randomness.
- **Performance Benchmarking:** Encryption and decryption times were optimized even for large message sizes.
- **Differential Cryptanalysis:** Demonstrated strong resistance with significant bit differences across multiple test pairs.

These tests confirm the robustness and efficiency of the proposed framework.

## Conclusion
This project successfully integrates dynamic key generation, advanced non-linear transformations, and adaptive S-box creation to form a secure cryptographic system. By combining lattice-based cryptography with SHA-256 integrity checks and character-to-name transformations, the framework presents a promising solution for secure data transmission in high-security applications.

## Installation

### Prerequisites
- [Git](https://git-scm.com/)
- [Python 3.x](https://www.python.org/) *(or your preferred programming environment)*
- Necessary libraries (refer to `requirements.txt`)

### Steps
1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/your-repo.git
   cd your-repo
   ```
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Build/Compile the project (if applicable):**
   ```bash
   make build
   ```

## Usage

### Encryption
To encrypt a message:
```bash
python encrypt.py --input "Your message here"
```
This will generate the ciphertext along with the dynamic S-box used during encryption.

### Decryption
To decrypt an encrypted message:
```bash
python decrypt.py --input "Encrypted message" --key "your_key" --sbox "sbox_values"
```

### Testing
Run the test suite:
```bash
python -m unittest discover tests
```

## References
- **Project Paper:** Sukash L, Ahmed Samathani M B, Sudharsan K, Vignesh V, Tamil Selvan R. *Integrating Textual Name Values and Dynamic Key Generation with Advanced Non-Linear Transformations for Encryption.* International Journal of Innovative Research in Technology, Volume 11 Issue 6, November 2024. [View Paper](./IJIRT169305_PAPER.pdf)
- Additional literature and sources are cited within the paper.

## Authors
- **Sukash L**
- **Ahmed Samathani M B**
- **Sudharsan K**
- **Vignesh V**
- **Tamil Selvan R**

## License
This project is licensed under the [MIT License](LICENSE).

## Acknowledgements
Special thanks to the International Journal of Innovative Research in Technology (IJIRT) for supporting and publishing this work.
