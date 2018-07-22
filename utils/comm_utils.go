package utils

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
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
func GetProbeId(id string) string {
	return Md5([]byte(id + strconv.Itoa(6101)))
}
func Base64Encode(input []byte) string {

	encodeString := base64.StdEncoding.EncodeToString(input)
	return encodeString
}

func Base64Decode(str string) []byte {
	var raw_data []byte
	raw_data, _ = base64.StdEncoding.DecodeString(str)
	return raw_data
}
