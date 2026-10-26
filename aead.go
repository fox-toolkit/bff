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

// scopedAEAD adds the scope of a frontend to the associated data of every operation. Data encrypted by one frontend
// fails to decrypt in another frontend that uses the same keys.
type scopedAEAD struct {
	AEAD
	scope string
}

func (a scopedAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return a.AEAD.Encrypt(plaintext, a.bind(associatedData))
}

func (a scopedAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return a.AEAD.Decrypt(ciphertext, a.bind(associatedData))
}

func (a scopedAEAD) bind(associatedData []byte) []byte {
	b := make([]byte, 0, len(associatedData)+1+len(a.scope))
	b = append(b, associatedData...)
	b = append(b, 0)
	return append(b, a.scope...)
}
