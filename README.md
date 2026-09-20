<p align="center">
  <strong>BeastX – PHP Source Code Protection Extension</strong>
</p>

<!-- <p align="center">
  <a href="https://github.com/arshidkv12/beastx/stargazers">
    <img src="https://img.shields.io/github/stars/arshidkv12/beastx" alt="GitHub stars">
  </a>
  <a href="https://github.com/arshidkv12/beastx/issues">
    <img src="https://img.shields.io/github/issues/arshidkv12/beastx" alt="GitHub issues">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/github/license/arshidkv12/beastx" alt="License">
  </a>
</p> -->


## Overview
PHP-Beast is a powerful PHP source code encryption module designed to protect your PHP applications from unauthorized access and reverse engineering. It encrypts PHP files at the source level while maintaining full compatibility with PHP execution environments.

## Features
- 🔒 Multiple Encryption Algorithms: Supports AES, DES, and Base64 encryption

- 🛡️ Security Enhancements: Customizable encryption keys and file headers

- 🏷️ Machine Binding: Restrict execution to specific machines via MAC addresses

- ⏰ Expiration Control: Set time limits for encrypted files

- 🔧 Easy Integration: Simple installation and configuration

- 🐛 Debug Mode: Debug decryption process when needed

- 📁 Large File Support: Handle files up to specified size limits

- 🔄 Cache System: Improve performance with configurable caching

## How to install?
```bash
pie install arshidkv12/beastx
```

## Function List

- `beast_encode_file()` — Encrypt a file

- `beast_avail_cache()` — Get available cache size

- `beast_support_filesize()` — Get max supported file size

- `beast_file_expire()` — Get file expiration time

- `beast_clean_cache()` — Clear all caches


## How to Encrypt a PHP File

Use the script `tools/encode_file.php` to encrypt a single PHP file.

```bash
php encode_file.php \
  --oldfile old_file_path \
  --newfile new_file_path \
  --encrypt DES \
  --expire "2026-10-10 10:10:10"
```

**Parameter Description**

- `--oldfile` : Path to the original PHP file to be encrypted

- `--newfile` : Path where the encrypted file will be saved

- `--encrypt` : Encryption algorithm (DES, AES, BASE64)

- `--expire` : Expiration date and time (YYYY-MM-DD HH:MM:SS)