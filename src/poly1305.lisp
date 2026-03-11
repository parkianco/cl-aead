;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; poly1305.lisp - Poly1305 MAC implementation
;;;;
;;;; Reference: RFC 8439 Section 2.5

(in-package #:cl-aead)

;;; ============================================================================
;;; Constants
;;; ============================================================================

(defconstant +poly1305-tag-size+ 16
  "Poly1305 tag size in bytes.")

(defconstant +poly1305-key-size+ 32
  "Poly1305 key size in bytes (r || s).")

;;; ============================================================================
;;; Poly1305 Implementation
;;; ============================================================================

(defun poly1305-clamp-r (r-bytes)
  "Clamp the r portion of the Poly1305 key per RFC 8439."
  (declare (type (simple-array (unsigned-byte 8) (16)) r-bytes))
  (let ((r (make-array 16 :element-type '(unsigned-byte 8))))
    (replace r r-bytes)
    ;; Clear top 4 bits of bytes 3, 7, 11, 15
    (setf (aref r 3)  (logand (aref r 3)  #x0f))
    (setf (aref r 7)  (logand (aref r 7)  #x0f))
    (setf (aref r 11) (logand (aref r 11) #x0f))
    (setf (aref r 15) (logand (aref r 15) #x0f))
    ;; Clear bottom 2 bits of bytes 4, 8, 12
    (setf (aref r 4)  (logand (aref r 4)  #xfc))
    (setf (aref r 8)  (logand (aref r 8)  #xfc))
    (setf (aref r 12) (logand (aref r 12) #xfc))
    r))

(defun le-bytes-to-integer (bytes)
  "Convert little-endian bytes to integer."
  (let ((result 0))
    (loop for i from (1- (length bytes)) downto 0
          do (setf result (logior (ash result 8) (aref bytes i))))
    result))

(defun integer-to-le-bytes (n len)
  "Convert integer to little-endian bytes of given length."
  (let ((result (make-array len :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for i from 0 below len
          do (setf (aref result i) (logand (ash n (- (* i 8))) #xff)))
    result))

(defun poly1305-mac (message key)
  "Compute Poly1305 MAC of MESSAGE using KEY.
   KEY must be 32 bytes: first 16 bytes are clamped r, last 16 bytes are s.
   Returns 16-byte tag."
  (declare (type (simple-array (unsigned-byte 8) (*)) message)
           (type (simple-array (unsigned-byte 8) (32)) key))
  (let* ((r-bytes (subseq key 0 16))
         (s-bytes (subseq key 16 32))
         (clamped-r (poly1305-clamp-r r-bytes))
         (r (le-bytes-to-integer clamped-r))
         (s (le-bytes-to-integer s-bytes))
         ;; Poly1305 prime: 2^130 - 5
         (p (- (ash 1 130) 5))
         (acc 0)
         (msg-len (length message)))
    ;; Process message in 16-byte blocks
    (loop for i from 0 below msg-len by 16
          for end = (min (+ i 16) msg-len)
          for block-len = (- end i)
          for block = (make-array (1+ block-len) :element-type '(unsigned-byte 8) :initial-element 0)
          do (replace block message :start2 i :end2 end)
             ;; Add 0x01 byte after message bytes (pad with implicit 1)
             (setf (aref block block-len) 1)
             (let ((n (le-bytes-to-integer block)))
               (setf acc (mod (* (+ acc n) r) p))))
    ;; Add s to accumulator
    (let ((tag (mod (+ acc s) (ash 1 128))))
      (integer-to-le-bytes tag 16))))

;;; End of poly1305.lisp
