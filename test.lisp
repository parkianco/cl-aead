;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

(load "cl-aead.asd")
(asdf:test-system :aead/test)
(format t "~&✓ aead tests passed!~%")
(quit)
