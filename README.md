# cl-aead

Pure Common Lisp AEAD (Authenticated Encryption with Associated Data) implementations with **zero external dependencies**.

## Features

- **ChaCha20-Poly1305**: RFC 8439 IETF variant
- **XChaCha20-Poly1305**: Extended nonce (24 bytes) variant
- **AES-256-GCM**: Galois/Counter Mode authenticated encryption
- **Pure Common Lisp**: No CFFI, no OpenSSL

## Installation

```lisp
(asdf:load-system :cl-aead)
```

## Quick Start

```lisp
(use-package :cl-aead)

;; ChaCha20-Poly1305 encryption
(let* ((key (random-bytes 32))
       (nonce (random-bytes 12))
       (plaintext #(1 2 3 4 5))
       (aad #(72 101 108 108 111)))  ; "Hello"
  (multiple-value-bind (ciphertext tag)
      (chacha20-poly1305-encrypt key nonce plaintext aad)
    ;; Decrypt
    (chacha20-poly1305-decrypt key nonce ciphertext tag aad)))
```

## API Reference

### ChaCha20-Poly1305

- `(chacha20-poly1305-encrypt key nonce plaintext &optional aad)` - Encrypt with authentication
- `(chacha20-poly1305-decrypt key nonce ciphertext tag &optional aad)` - Decrypt and verify

### XChaCha20-Poly1305

- `(xchacha20-poly1305-encrypt key nonce plaintext &optional aad)` - Extended nonce encryption
- `(xchacha20-poly1305-decrypt key nonce ciphertext tag &optional aad)` - Extended nonce decryption

### AES-256-GCM

- `(aes-gcm-encrypt key nonce plaintext &optional aad)` - AES-GCM encryption
- `(aes-gcm-decrypt key nonce ciphertext tag &optional aad)` - AES-GCM decryption

## Testing

```lisp
(asdf:test-system :cl-aead)
```

## License

BSD-3-Clause

Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
