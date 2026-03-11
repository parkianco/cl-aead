;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; aead.lisp - High-level AEAD API (ChaCha20-Poly1305, XChaCha20-Poly1305, AES-256-GCM)
;;;;
;;;; Reference: RFC 8439 (ChaCha20-Poly1305)

(in-package #:cl-aead)

;;; ============================================================================
;;; Utility Functions
;;; ============================================================================

(defun pad-to-16 (len)
  "Calculate padding needed to reach next 16-byte boundary."
  (let ((rem (mod len 16)))
    (if (zerop rem) 0 (- 16 rem))))

(defun u64-to-le-bytes (n)
  "Convert 64-bit integer to 8 little-endian bytes."
  (let ((result (make-array 8 :element-type '(unsigned-byte 8))))
    (loop for i from 0 below 8
          do (setf (aref result i) (logand (ash n (- (* i 8))) #xff)))
    result))

(defun construct-poly1305-data (aad ciphertext)
  "Construct Poly1305 input per RFC 8439 Section 2.8."
  (let* ((aad-len (length aad))
         (ct-len (length ciphertext))
         (aad-pad (pad-to-16 aad-len))
         (ct-pad (pad-to-16 ct-len))
         (total-len (+ aad-len aad-pad ct-len ct-pad 16))
         (data (make-array total-len :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; AAD
    (replace data aad)
    ;; AAD padding (already zeroed)
    ;; Ciphertext
    (replace data ciphertext :start1 (+ aad-len aad-pad))
    ;; Ciphertext padding (already zeroed)
    ;; Length of AAD (8 bytes, little-endian)
    (replace data (u64-to-le-bytes aad-len) :start1 (+ aad-len aad-pad ct-len ct-pad))
    ;; Length of ciphertext (8 bytes, little-endian)
    (replace data (u64-to-le-bytes ct-len) :start1 (+ aad-len aad-pad ct-len ct-pad 8))
    data))

;;; ============================================================================
;;; ChaCha20-Poly1305 AEAD (RFC 8439)
;;; ============================================================================

(defun chacha20-poly1305-encrypt (key nonce plaintext &optional (aad (make-array 0 :element-type '(unsigned-byte 8))))
  "Encrypt PLAINTEXT using ChaCha20-Poly1305 AEAD.

   KEY: 32-byte key
   NONCE: 12-byte nonce
   PLAINTEXT: byte vector to encrypt
   AAD: additional authenticated data (optional)

   Returns (VALUES ciphertext tag) where tag is 16 bytes."
  (declare (type (simple-array (unsigned-byte 8) (32)) key)
           (type (simple-array (unsigned-byte 8) (12)) nonce)
           (type (simple-array (unsigned-byte 8) (*)) plaintext aad))
  ;; Generate Poly1305 one-time key (first 32 bytes of ChaCha20 with counter=0)
  (let* ((poly-key-block (chacha20-block key nonce 0))
         (poly-key (subseq poly-key-block 0 32))
         ;; Encrypt plaintext with counter starting at 1
         (ciphertext (chacha20-encrypt plaintext key nonce 1))
         ;; Construct Poly1305 data
         (poly-data (construct-poly1305-data aad ciphertext))
         ;; Compute tag
         (tag (poly1305-mac poly-data poly-key)))
    (values ciphertext tag)))

(defun chacha20-poly1305-decrypt (key nonce ciphertext tag &optional (aad (make-array 0 :element-type '(unsigned-byte 8))))
  "Decrypt CIPHERTEXT using ChaCha20-Poly1305 AEAD.

   KEY: 32-byte key
   NONCE: 12-byte nonce
   CIPHERTEXT: byte vector to decrypt
   TAG: 16-byte authentication tag
   AAD: additional authenticated data (optional)

   Returns plaintext on success, signals error on authentication failure."
  (declare (type (simple-array (unsigned-byte 8) (32)) key)
           (type (simple-array (unsigned-byte 8) (12)) nonce)
           (type (simple-array (unsigned-byte 8) (*)) ciphertext aad)
           (type (simple-array (unsigned-byte 8) (16)) tag))
  ;; Generate Poly1305 one-time key
  (let* ((poly-key-block (chacha20-block key nonce 0))
         (poly-key (subseq poly-key-block 0 32))
         ;; Verify tag
         (poly-data (construct-poly1305-data aad ciphertext))
         (expected-tag (poly1305-mac poly-data poly-key)))
    (unless (ct-bytes= tag expected-tag)
      (error "Authentication failed: invalid tag"))
    ;; Decrypt (same as encrypt - XOR)
    (chacha20-encrypt ciphertext key nonce 1)))

;;; ============================================================================
;;; XChaCha20-Poly1305 AEAD
;;; ============================================================================

(defun xchacha20-poly1305-encrypt (key nonce plaintext &optional (aad (make-array 0 :element-type '(unsigned-byte 8))))
  "Encrypt PLAINTEXT using XChaCha20-Poly1305 AEAD with extended 24-byte nonce.

   KEY: 32-byte key
   NONCE: 24-byte extended nonce
   PLAINTEXT: byte vector to encrypt
   AAD: additional authenticated data (optional)

   Returns (VALUES ciphertext tag)."
  (declare (type (simple-array (unsigned-byte 8) (32)) key)
           (type (simple-array (unsigned-byte 8) (24)) nonce)
           (type (simple-array (unsigned-byte 8) (*)) plaintext aad))
  ;; Derive subkey using HChaCha20
  (let* ((subkey (hchacha20 key (subseq nonce 0 16)))
         ;; Use last 8 bytes of nonce with 4-byte zero prefix
         (sub-nonce (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace sub-nonce nonce :start2 16)
    (chacha20-poly1305-encrypt subkey sub-nonce plaintext aad)))

(defun xchacha20-poly1305-decrypt (key nonce ciphertext tag &optional (aad (make-array 0 :element-type '(unsigned-byte 8))))
  "Decrypt CIPHERTEXT using XChaCha20-Poly1305 AEAD with extended 24-byte nonce.

   KEY: 32-byte key
   NONCE: 24-byte extended nonce
   CIPHERTEXT: byte vector to decrypt
   TAG: 16-byte authentication tag
   AAD: additional authenticated data (optional)

   Returns plaintext on success, signals error on authentication failure."
  (declare (type (simple-array (unsigned-byte 8) (32)) key)
           (type (simple-array (unsigned-byte 8) (24)) nonce)
           (type (simple-array (unsigned-byte 8) (*)) ciphertext aad)
           (type (simple-array (unsigned-byte 8) (16)) tag))
  ;; Derive subkey using HChaCha20
  (let* ((subkey (hchacha20 key (subseq nonce 0 16)))
         ;; Use last 8 bytes of nonce with 4-byte zero prefix
         (sub-nonce (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace sub-nonce nonce :start2 16)
    (chacha20-poly1305-decrypt subkey sub-nonce ciphertext tag aad)))

;;; ============================================================================
;;; High-Level AEAD API
;;; ============================================================================

(defun generate-random-nonce (size)
  "Generate cryptographically random nonce of given SIZE."
  (let ((nonce (make-array size :element-type '(unsigned-byte 8))))
    ;; Use SBCL's random state or /dev/urandom
    #+sbcl
    (with-open-file (f "/dev/urandom" :element-type '(unsigned-byte 8))
      (read-sequence nonce f))
    #-sbcl
    (loop for i from 0 below size
          do (setf (aref nonce i) (random 256)))
    nonce))

(defun aead-encrypt (key plaintext &key (algorithm :chacha20-poly1305) nonce (aad (make-array 0 :element-type '(unsigned-byte 8))))
  "High-level AEAD encryption.

   ALGORITHM: :chacha20-poly1305, :xchacha20-poly1305, or :aes256-gcm
   Returns (VALUES ciphertext tag nonce)"
  (let* ((nonce-size (ecase algorithm
                       (:chacha20-poly1305 12)
                       (:xchacha20-poly1305 24)
                       (:aes256-gcm 12)))
         (nonce (or nonce (generate-random-nonce nonce-size))))
    (multiple-value-bind (ciphertext tag)
        (ecase algorithm
          (:chacha20-poly1305
           (chacha20-poly1305-encrypt key nonce plaintext aad))
          (:xchacha20-poly1305
           (xchacha20-poly1305-encrypt key nonce plaintext aad))
          (:aes256-gcm
           (aes256-gcm-encrypt key nonce plaintext aad)))
      (values ciphertext tag nonce))))

(defun aead-decrypt (key ciphertext tag nonce &key (algorithm :chacha20-poly1305) (aad (make-array 0 :element-type '(unsigned-byte 8))))
  "High-level AEAD decryption.

   ALGORITHM: :chacha20-poly1305, :xchacha20-poly1305, or :aes256-gcm
   Returns plaintext on success, signals error on authentication failure."
  (ecase algorithm
    (:chacha20-poly1305
     (chacha20-poly1305-decrypt key nonce ciphertext tag aad))
    (:xchacha20-poly1305
     (xchacha20-poly1305-decrypt key nonce ciphertext tag aad))
    (:aes256-gcm
     (aes256-gcm-decrypt key nonce ciphertext tag aad))))

;;; End of aead.lisp
