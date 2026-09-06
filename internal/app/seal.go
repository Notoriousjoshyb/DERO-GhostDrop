package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

func randReader() io.Reader { return rand.Reader }

// sealWithProgress seals like SealFile but reports plaintext progress per chunk.
func sealWithProgress(srcPath, dstPath string, key [32]byte, fn func(written, total int64)) (string, string, int64, error) {
	in, err := os.Open(srcPath)
	if err != nil {
		return "", "", 0, err
	}
	defer in.Close()
	var total int64
	if fi, err := in.Stat(); err == nil {
		total = fi.Size()
	}
	out, err := os.Create(dstPath)
	if err != nil {
		return "", "", 0, err
	}
	defer out.Close()
	header := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, header); err != nil {
		return "", "", 0, err
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return "", "", 0, err
	}
	plainH := sha256.New()
	cipherH := sha256.New()
	mw := io.MultiWriter(out, cipherH)
	if _, err := mw.Write([]byte(FileMagic)); err != nil {
		return "", "", 0, err
	}
	if _, err := mw.Write(header); err != nil {
		return "", "", 0, err
	}
	buf := make([]byte, ChunkSize)
	defer Wipe(buf)
	var index uint64
	var done int64
	for {
		nr, rerr := io.ReadFull(in, buf)
		if nr > 0 {
			chunk := buf[:nr]
			plainH.Write(chunk)
			nonce := chunkNonce(header, index)
			sealed := aead.Seal(nil, nonce[:], chunk, nil)
			var lb [4]byte
			binary.BigEndian.PutUint32(lb[:], uint32(len(sealed)))
			if _, err := mw.Write(lb[:]); err != nil {
				return "", "", 0, err
			}
			if _, err := mw.Write(sealed); err != nil {
				return "", "", 0, err
			}
			done += int64(nr)
			index++
			if fn != nil {
				fn(done, total)
			}
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return "", "", 0, rerr
		}
	}
	return hex.EncodeToString(cipherH.Sum(nil)), hex.EncodeToString(plainH.Sum(nil)), done, nil
}
