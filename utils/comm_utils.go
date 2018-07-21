package utils

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
)

func Md5(b []byte) string {
	h := md5.New()
	h.Write(b)
	cipherStr := h.Sum(nil)
	return hex.EncodeToString(cipherStr)
}

func Sha256(b []byte) string {
	h := sha256.New()
	h.Write([]byte(b))
	bs := h.Sum(nil)
	return hex.EncodeToString(bs)
}

//生成probe_id
func GetProbeId(id string, time int64) string {
	val := "123"
	return val
}
