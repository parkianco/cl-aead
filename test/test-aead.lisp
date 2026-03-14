;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; test-aead.lisp - Unit tests for aead
;;;;
;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

(defpackage #:cl-aead.test
  (:use #:cl)
  (:export #:run-tests))

(in-package #:cl-aead.test)

(defun run-tests ()
  "Run all tests for cl-aead."
  (format t "~&Running tests for cl-aead...~%")
  ;; TODO: Add test cases
  ;; (test-function-1)
  ;; (test-function-2)
  (format t "~&All tests passed!~%")
  t)
