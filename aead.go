// Copyright 2026 Sylvain Müller. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// at https://github.com/fox-toolkit/bff/blob/main/LICENSE.txt.

package bff

// AEAD provides authenticated encryption with associated data. A [Frontend] uses it to encrypt its sessions. Its
// method set matches tink.AEAD. Key rotation is the responsibility of the implementation.
type AEAD interface {
	Encrypt(plaintext, associatedData []byte) ([]byte, error)
	Decrypt(ciphertext, associatedData []byte) ([]byte, error)
}
