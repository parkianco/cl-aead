;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; ChaCha20 implementation per RFC 8439

(in-package #:cl-aead)

(declaim (optimize (speed 3) (safety 1) (debug 0)))

;;; ============================================================================
;;; ChaCha20 Constants
;;; ============================================================================

(defconstant +chacha20-block-size+ 64
  "ChaCha20 block size in bytes.")

(defconstant +chacha20-key-size+ 32
  "ChaCha20 key size in bytes (256 bits).")

(defconstant +chacha20-nonce-size+ 12
  "ChaCha20 nonce size in bytes (96 bits).")

(defconstant +xchacha20-nonce-size+ 24
  "XChaCha20 extended nonce size in bytes (192 bits).")

;;; ============================================================================
;;; ChaCha20 Quarter Round (RFC 8439 Section 2.1)
;;; ============================================================================

(defmacro chacha-rotl32 (x n)
  "Left rotate 32-bit value X by N bits."
  `(logand #xffffffff
           (logior (ash ,x ,n)
                   (ash ,x (- ,n 32)))))

(defun chacha20-quarter-round! (state a b c d)
  "Apply ChaCha20 quarter round to STATE at indices A, B, C, D."
  (declare (type (simple-array (unsigned-byte 32) (16)) state)
           (type (integer 0 15) a b c d)
           (optimize (speed 3) (safety 0)))
  (setf (aref state a) (logand (+ (aref state a) (aref state b)) #xffffffff))
  (setf (aref state d) (chacha-rotl32 (logxor (aref state d) (aref state a)) 16))
  (setf (aref state c) (logand (+ (aref state c) (aref state d)) #xffffffff))
  (setf (aref state b) (chacha-rotl32 (logxor (aref state b) (aref state c)) 12))
  (setf (aref state a) (logand (+ (aref state a) (aref state b)) #xffffffff))
  (setf (aref state d) (chacha-rotl32 (logxor (aref state d) (aref state a)) 8))
  (setf (aref state c) (logand (+ (aref state c) (aref state d)) #xffffffff))
  (setf (aref state b) (chacha-rotl32 (logxor (aref state b) (aref state c)) 7)))

;;; ============================================================================
;;; ChaCha20 State Initialization (RFC 8439 Section 2.3)
;;; ============================================================================

(defun chacha20-init-state (key nonce counter)
  "Initialize ChaCha20 state matrix from KEY, NONCE, and COUNTER.

State matrix layout:
  [const  const  const  const ]
  [key    key    key    key   ]
  [key    key    key    key   ]
  [count  nonce  nonce  nonce ]"
  (declare (type (simple-array (unsigned-byte 8) (32)) key)
           (type (simple-array (unsigned-byte 8) (12)) nonce)
           (type (unsigned-byte 32) counter))
  (let ((state (make-array 16 :element-type '(unsigned-byte 32))))
    ;; Constants: "expand 32-byte k"
    (setf (aref state 0) #x61707865  ; "expa"
          (aref state 1) #x3320646e  ; "nd 3"
          (aref state 2) #x79622d32  ; "2-by"
          (aref state 3) #x6b206574) ; "te k"
    ;; Key (8 words, little-endian)
    (loop for i from 0 below 8
          for offset = (* i 4)
          do (setf (aref state (+ 4 i))
                   (logior (aref key offset)
                           (ash (aref key (+ offset 1)) 8)
                           (ash (aref key (+ offset 2)) 16)
                           (ash (aref key (+ offset 3)) 24))))
    ;; Counter
    (setf (aref state 12) counter)
    ;; Nonce (3 words, little-endian)
    (loop for i from 0 below 3
          for offset = (* i 4)
          do (setf (aref state (+ 13 i))
                   (logior (aref nonce offset)
                           (ash (aref nonce (+ offset 1)) 8)
                           (ash (aref nonce (+ offset 2)) 16)
                           (ash (aref nonce (+ offset 3)) 24))))
    state))

;;; ============================================================================
;;; ChaCha20 Block Function (RFC 8439 Section 2.3)
;;; ============================================================================

(defun chacha20-block (key nonce counter)
  "Generate one ChaCha20 keystream block (64 bytes)."
  (let ((state (chacha20-init-state key nonce counter))
        (working (make-array 16 :element-type '(unsigned-byte 32))))
    ;; Copy initial state
    (replace working state)
    ;; 20 rounds (10 double-rounds)
    (dotimes (i 10)
      ;; Column rounds
      (chacha20-quarter-round! working 0 4 8 12)
      (chacha20-quarter-round! working 1 5 9 13)
      (chacha20-quarter-round! working 2 6 10 14)
      (chacha20-quarter-round! working 3 7 11 15)
      ;; Diagonal rounds
      (chacha20-quarter-round! working 0 5 10 15)
      (chacha20-quarter-round! working 1 6 11 12)
      (chacha20-quarter-round! working 2 7 8 13)
      (chacha20-quarter-round! working 3 4 9 14))
    ;; Add initial state
    (dotimes (i 16)
      (setf (aref working i) (logand (+ (aref working i) (aref state i)) #xffffffff)))
    ;; Serialize to bytes (little-endian)
    (let ((result (make-array 64 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 16
            for word = (aref working i)
            for offset = (* i 4)
            do (setf (aref result offset) (logand word #xff)
                     (aref result (+ offset 1)) (logand (ash word -8) #xff)
                     (aref result (+ offset 2)) (logand (ash word -16) #xff)
                     (aref result (+ offset 3)) (logand (ash word -24) #xff)))
      result)))

;;; ============================================================================
;;; HChaCha20 (draft-irtf-cfrg-xchacha Section 2.2)
;;; ============================================================================

(defun hchacha20 (key nonce)
  "HChaCha20: Key derivation function for XChaCha20.

PARAMETERS:
  KEY - 32-byte key
  NONCE - 16-byte input (first 16 bytes of XChaCha20's 24-byte nonce)

RETURNS:
  32-byte derived subkey"
  (declare (type (simple-array (unsigned-byte 8) (32)) key)
           (type (simple-array (unsigned-byte 8) (16)) nonce))
  (let ((state (make-array 16 :element-type '(unsigned-byte 32))))
    ;; Constants
    (setf (aref state 0) #x61707865
          (aref state 1) #x3320646e
          (aref state 2) #x79622d32
          (aref state 3) #x6b206574)
    ;; Key
    (loop for i from 0 below 8
          for offset = (* i 4)
          do (setf (aref state (+ 4 i))
                   (logior (aref key offset)
                           (ash (aref key (+ offset 1)) 8)
                           (ash (aref key (+ offset 2)) 16)
                           (ash (aref key (+ offset 3)) 24))))
    ;; Nonce (4 words, replaces counter + nonce)
    (loop for i from 0 below 4
          for offset = (* i 4)
          do (setf (aref state (+ 12 i))
                   (logior (aref nonce offset)
                           (ash (aref nonce (+ offset 1)) 8)
                           (ash (aref nonce (+ offset 2)) 16)
                           (ash (aref nonce (+ offset 3)) 24))))
    ;; 20 rounds
    (dotimes (i 10)
      (chacha20-quarter-round! state 0 4 8 12)
      (chacha20-quarter-round! state 1 5 9 13)
      (chacha20-quarter-round! state 2 6 10 14)
      (chacha20-quarter-round! state 3 7 11 15)
      (chacha20-quarter-round! state 0 5 10 15)
      (chacha20-quarter-round! state 1 6 11 12)
      (chacha20-quarter-round! state 2 7 8 13)
      (chacha20-quarter-round! state 3 4 9 14))
    ;; Extract subkey: first 4 words + last 4 words
    (let ((subkey (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 4
            for word = (aref state i)
            for offset = (* i 4)
            do (setf (aref subkey offset) (logand word #xff)
                     (aref subkey (+ offset 1)) (logand (ash word -8) #xff)
                     (aref subkey (+ offset 2)) (logand (ash word -16) #xff)
                     (aref subkey (+ offset 3)) (logand (ash word -24) #xff)))
      (loop for i from 0 below 4
            for word = (aref state (+ 12 i))
            for offset = (+ 16 (* i 4))
            do (setf (aref subkey offset) (logand word #xff)
                     (aref subkey (+ offset 1)) (logand (ash word -8) #xff)
                     (aref subkey (+ offset 2)) (logand (ash word -16) #xff)
                     (aref subkey (+ offset 3)) (logand (ash word -24) #xff)))
      subkey)))

;;; ============================================================================
;;; ChaCha20 Stream Encryption
;;; ============================================================================

(defun chacha20-encrypt (plaintext key nonce &optional (counter 0))
  "Encrypt PLAINTEXT with ChaCha20 stream cipher.

PARAMETERS:
  PLAINTEXT - data to encrypt
  KEY - 32-byte key
  NONCE - 12-byte nonce
  COUNTER - initial block counter (default 0)

RETURNS:
  Ciphertext of same length as plaintext"
  (declare (type (simple-array (unsigned-byte 8) (32)) key)
           (type (simple-array (unsigned-byte 8) (12)) nonce))
  (let* ((len (length plaintext))
         (ciphertext (make-array len :element-type '(unsigned-byte 8))))
    (loop for block-counter from counter
          for offset from 0 below len by 64
          for keystream = (chacha20-block key nonce block-counter)
          for block-len = (min 64 (- len offset))
          do (loop for i from 0 below block-len
                   do (setf (aref ciphertext (+ offset i))
                            (logxor (aref plaintext (+ offset i))
                                    (aref keystream i)))))
    ciphertext))
