;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; AES-GCM implementation per NIST SP 800-38D

(in-package #:cl-aead)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; GCM Constants
;;; ============================================================================

(defconstant +aes-gcm-nonce-size+ 12
  "AES-GCM recommended nonce size (96 bits).")

(defconstant +aes-gcm-tag-size+ 16
  "AES-GCM tag size (128 bits).")

;;; ============================================================================
;;; GCM Counter Increment (NIST SP 800-38D Section 6.2)
;;; ============================================================================

(defun gcm-inc32 (counter)
  "Increment the rightmost 32 bits of COUNTER (big-endian)."
  (declare (type (simple-array (unsigned-byte 8) (16)) counter))
  (let ((result (copy-seq counter)))
    ;; Increment bytes 12-15 as big-endian 32-bit integer
    (loop for i from 15 downto 12
          do (if (< (aref result i) 255)
                 (progn
                   (incf (aref result i))
                   (return))
                 (setf (aref result i) 0)))
    result))

;;; ============================================================================
;;; GHASH (NIST SP 800-38D Section 6.4)
;;; ============================================================================

(defun gf128-mul (x h)
  "Multiply X and H in GF(2^128) with the GCM reduction polynomial."
  (declare (type (simple-array (unsigned-byte 8) (16)) x h))
  (let ((z (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
        (v (copy-seq h)))
    ;; Process each bit of X
    (dotimes (i 16)
      (dotimes (j 8)
        ;; If bit (i*8 + j) of X is set, Z = Z XOR V
        (when (logbitp (- 7 j) (aref x i))
          (dotimes (k 16)
            (setf (aref z k) (logxor (aref z k) (aref v k)))))
        ;; V = V >> 1, with GCM reduction
        (let ((lsb (logand (aref v 15) 1)))
          ;; Right shift V by 1 bit
          (loop for k from 15 downto 1
                do (setf (aref v k)
                         (logior (ash (aref v k) -1)
                                 (ash (logand (aref v (1- k)) 1) 7))))
          (setf (aref v 0) (ash (aref v 0) -1))
          ;; If LSB was 1, XOR with reduction polynomial R = 0xE1 << 120
          (when (= lsb 1)
            (setf (aref v 0) (logxor (aref v 0) #xe1))))))
    z))

(defun ghash (h data)
  "Compute GHASH of DATA using hash subkey H."
  (declare (type (simple-array (unsigned-byte 8) (16)) h))
  (let ((y (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
        (block (make-array 16 :element-type '(unsigned-byte 8))))
    (loop for offset from 0 below (length data) by 16
          do (fill block 0)
             (let ((block-len (min 16 (- (length data) offset))))
               (replace block data :start2 offset :end2 (+ offset block-len)))
             ;; Y = (Y XOR block) * H
             (dotimes (i 16)
               (setf (aref block i) (logxor (aref y i) (aref block i))))
             (setf y (gf128-mul block h)))
    y))

;;; ============================================================================
;;; AES-256-GCM Encryption (NIST SP 800-38D Section 7.1)
;;; ============================================================================

(defun aes256-gcm-encrypt (key iv plaintext &optional (aad #()))
  "Encrypt PLAINTEXT with AES-256-GCM authenticated encryption.

PARAMETERS:
  KEY - 32-byte key
  IV - 12-byte initialization vector (MUST be unique per encryption)
  PLAINTEXT - data to encrypt
  AAD - additional authenticated data (optional)

RETURNS:
  (VALUES ciphertext tag)

SECURITY:
  NEVER reuse IV with the same key."
  (declare (type (simple-array (unsigned-byte 8) (32)) key)
           (type (simple-array (unsigned-byte 8) (12)) iv))
  (let* ((round-keys (aes-key-expansion key))
         (p-len (length plaintext))
         (aad-len (length aad))
         (ciphertext (make-array p-len :element-type '(unsigned-byte 8)))
         ;; Generate hash subkey H = E(K, 0^128)
         (h-block (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (h (aes-encrypt-block h-block round-keys))
         ;; Generate initial counter J0 = IV || 0^31 || 1
         (j0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))

    ;; Set up J0 = IV || 0^31 || 1
    (replace j0 iv)
    (setf (aref j0 15) 1)

    ;; CTR mode encryption starting from J0 + 1
    (let ((counter (gcm-inc32 j0)))
      (loop for i from 0 below p-len by 16
            do (let* ((encrypted-counter (aes-encrypt-block counter round-keys))
                      (block-len (min 16 (- p-len i))))
                 (dotimes (j block-len)
                   (setf (aref ciphertext (+ i j))
                         (logxor (aref plaintext (+ i j))
                                 (aref encrypted-counter j))))
                 (setf counter (gcm-inc32 counter)))))

    ;; Compute authentication tag using GHASH
    (let* ((aad-padded-len (* 16 (ceiling aad-len 16)))
           (ct-padded-len (* 16 (ceiling p-len 16)))
           (ghash-input (make-array (+ aad-padded-len ct-padded-len 16)
                                    :element-type '(unsigned-byte 8)
                                    :initial-element 0)))
      ;; Copy AAD with padding
      (when (plusp aad-len)
        (replace ghash-input aad))
      ;; Copy ciphertext with padding
      (when (plusp p-len)
        (replace ghash-input ciphertext :start1 aad-padded-len))
      ;; Append lengths (big-endian 64-bit each)
      (let ((len-offset (+ aad-padded-len ct-padded-len))
            (aad-bits (* aad-len 8))
            (ct-bits (* p-len 8)))
        (loop for i from 0 below 8
              do (setf (aref ghash-input (+ len-offset i))
                       (ldb (byte 8 (* 8 (- 7 i))) aad-bits)))
        (loop for i from 0 below 8
              do (setf (aref ghash-input (+ len-offset 8 i))
                       (ldb (byte 8 (* 8 (- 7 i))) ct-bits))))

      ;; S = GHASH(H, ghash-input)
      (let* ((s (ghash h ghash-input))
             ;; Tag = S XOR E(K, J0)
             (e-j0 (aes-encrypt-block j0 round-keys))
             (tag (make-array 16 :element-type '(unsigned-byte 8))))
        (dotimes (i 16)
          (setf (aref tag i) (logxor (aref s i) (aref e-j0 i))))
        (values ciphertext tag)))))

;;; ============================================================================
;;; AES-256-GCM Decryption (NIST SP 800-38D Section 7.2)
;;; ============================================================================

(defun aes256-gcm-decrypt (key iv ciphertext tag &optional (aad #()))
  "Decrypt CIPHERTEXT with AES-256-GCM authenticated decryption.

PARAMETERS:
  KEY - 32-byte key
  IV - 12-byte initialization vector (must match encryption)
  CIPHERTEXT - encrypted data
  TAG - 16-byte authentication tag
  AAD - additional authenticated data (must match encryption)

RETURNS:
  Decrypted plaintext if authentication succeeds

SIGNALS:
  Error if authentication fails"
  (declare (type (simple-array (unsigned-byte 8) (32)) key)
           (type (simple-array (unsigned-byte 8) (12)) iv)
           (type (simple-array (unsigned-byte 8) (16)) tag))
  (let* ((round-keys (aes-key-expansion key))
         (c-len (length ciphertext))
         (aad-len (length aad))
         (plaintext (make-array c-len :element-type '(unsigned-byte 8)))
         ;; Generate hash subkey H
         (h-block (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (h (aes-encrypt-block h-block round-keys))
         ;; Generate J0
         (j0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))

    ;; Set up J0 = IV || 0^31 || 1
    (replace j0 iv)
    (setf (aref j0 15) 1)

    ;; VERIFY TAG BEFORE DECRYPTION
    (let* ((aad-padded-len (* 16 (ceiling aad-len 16)))
           (ct-padded-len (* 16 (ceiling c-len 16)))
           (ghash-input (make-array (+ aad-padded-len ct-padded-len 16)
                                    :element-type '(unsigned-byte 8)
                                    :initial-element 0)))
      (when (plusp aad-len)
        (replace ghash-input aad))
      (when (plusp c-len)
        (replace ghash-input ciphertext :start1 aad-padded-len))
      (let ((len-offset (+ aad-padded-len ct-padded-len))
            (aad-bits (* aad-len 8))
            (ct-bits (* c-len 8)))
        (loop for i from 0 below 8
              do (setf (aref ghash-input (+ len-offset i))
                       (ldb (byte 8 (* 8 (- 7 i))) aad-bits)))
        (loop for i from 0 below 8
              do (setf (aref ghash-input (+ len-offset 8 i))
                       (ldb (byte 8 (* 8 (- 7 i))) ct-bits))))

      (let* ((s (ghash h ghash-input))
             (e-j0 (aes-encrypt-block j0 round-keys))
             (computed-tag (make-array 16 :element-type '(unsigned-byte 8))))
        (dotimes (i 16)
          (setf (aref computed-tag i) (logxor (aref s i) (aref e-j0 i))))

        ;; Constant-time tag verification
        (unless (ct-bytes= tag computed-tag)
          (error "AES-GCM authentication failed: tag mismatch"))))

    ;; Decrypt (CTR mode)
    (let ((counter (gcm-inc32 j0)))
      (loop for i from 0 below c-len by 16
            do (let* ((encrypted-counter (aes-encrypt-block counter round-keys))
                      (block-len (min 16 (- c-len i))))
                 (dotimes (j block-len)
                   (setf (aref plaintext (+ i j))
                         (logxor (aref ciphertext (+ i j))
                                 (aref encrypted-counter j))))
                 (setf counter (gcm-inc32 counter)))))
    plaintext))
