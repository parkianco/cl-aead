;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; cl-aead - Pure Common Lisp AEAD (Authenticated Encryption with Associated Data)

(asdf:defsystem #:cl-aead
  :description "Pure Common Lisp AEAD implementations: ChaCha20-Poly1305, XChaCha20-Poly1305, AES-256-GCM"
  :author "Parkian Company LLC"
  :license "BSD-3-Clause"
  :version "1.0.0"
  :serial t
  :components ((:file "package")
               (:module "src"
                :serial t
                :components ((:file "util")
                             (:file "aes")
                             (:file "gcm")
                             (:file "chacha20")
                             (:file "poly1305")
                             (:file "aead")))))

(asdf:defsystem #:cl-aead/test
  :description "Tests for cl-aead"
  :depends-on (#:cl-aead)
  :serial t
  :components ((:module "test"
                :components ((:file "tests"))))
  :perform (asdf:test-op (op c)
             (let ((result (uiop:symbol-call :cl-aead-test :run-all-tests)))
               (unless result
                 (error "Tests failed")))))
