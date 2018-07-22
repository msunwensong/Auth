package utils

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	ct "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"

	"github.com/cihub/seelog"
	//    "path/filepath"
	//    "strings"
)

func AAAAA() {}

//获取指定目录下的所有指定后缀的文件
func ListDir(dirPth, suffix string) []string {
	//fmt.Println(dirPth)
	dir, err := ioutil.ReadDir(dirPth)
	if err != nil {
		return nil
	}
	PthSep := string(os.PathSeparator)
	//    suffix = strings.ToUpper(suffix) //忽略后缀匹配的大小写
	files := make([]string, 0, 10)
	for _, fi := range dir {

		if fi.IsDir() { // 忽略目录
			//files1 = append(files1, dirPth+PthSep+fi.Name())
			//ListDir(dirPth + PthSep + fi.Name())
			continue
		} else {
			name := fi.Name()
			if strings.HasSuffix(name, suffix) {
				files = append(files, dirPth+PthSep+name)
			}
		}
	}

	return files
}

func ReadLines() {
	f, err := os.Open("readme.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	rd := bufio.NewReader(f)
	n := 0
	for {
		line, _, err := rd.ReadLine() //以'\n'为结束符读入一行
		if err != nil || io.EOF == err {
			//fmt.Println(line)
			break
		}

		n++
		fmt.Println(n, string(line))
	}
}

func AESCBCDecrypter(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(plaintext, ciphertext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.
	paddingLen := int(plaintext[len(plaintext)-1])
	if paddingLen < 0 || paddingLen > aes.BlockSize {
		return nil, errors.New("Invalid padding length")
	}

	return plaintext[0 : len(plaintext)-paddingLen], nil
}

/*
func AESCBCDecrypterWithIV(key []byte, ciphertext, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(plaintext, ciphertext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.
	paddingLen := int(plaintext[len(plaintext)-1])
	if paddingLen < 0 || paddingLen > aes.BlockSize {
		return nil, errors.New("Invalid padding length")
	}

	return plaintext[0 : len(plaintext)-paddingLen], nil
}
*/
func AESCBCEncrypter(key []byte, plaintext []byte) ([]byte, error) {
	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.

	paddingLen := len(plaintext) % aes.BlockSize

	if paddingLen != 0 {
		paddingLen = aes.BlockSize - paddingLen
	} else {
		paddingLen = aes.BlockSize
	}

	//	padding := make([]byte, paddingLen)

	//	for i, _ := range padding {
	//		padding[i] = byte(paddingLen)
	//	}
	padding := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	//padding := bytes.Repeat(byte(paddingLen), paddingLen)

	plaintext = append(plaintext, padding...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(ct.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	return ciphertext, nil
}

func AESCBCEncrypterWithIV(key []byte, plaintext []byte, iv []byte) ([]byte, error) {
	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.

	paddingLen := len(plaintext) % aes.BlockSize

	if paddingLen != 0 {
		paddingLen = aes.BlockSize - paddingLen
	} else {
		paddingLen = aes.BlockSize
	}

	//	padding := make([]byte, paddingLen)

	//	for i, _ := range padding {
	//		padding[i] = byte(paddingLen)
	//	}
	padding := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	//padding := bytes.Repeat(byte(paddingLen), paddingLen)

	plaintext = append(plaintext, padding...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, len(plaintext))
	//	iv := ciphertext[:aes.BlockSize]
	//	if _, err := io.ReadFull(ct.Reader, iv); err != nil {
	//		return nil, err
	//	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	return ciphertext, nil
}

func GetKey() []byte {
	buf := make([]byte, 16)

	rand.Read(buf)

	return buf
}

func ParseToken(token string, skey []byte) (probeId string, key []byte, createTime int64, err error) {
	var raw_data []byte

	raw_data, err = base64.StdEncoding.DecodeString(token)
	if err != nil {
		seelog.Error(err)
		return
	}

	//seelog.Debugf("token raw_data len = %d", len(raw_data))

	pt, err1 := AesGcmDecrypter(skey, raw_data)
	if err1 != nil {
		err = err1
		seelog.Error(err)
		return
	}

	if len(pt) != 40 {
		err = errors.New("错误的token长度")
		seelog.Errorf("错误的token长度: %d", len(pt))
		return
	}

	createTime = int64(binary.BigEndian.Uint64(pt))
	key = pt[8:24]
	probeId = hex.EncodeToString(pt[24:])

	err = nil

	return
}

func AesGcmEncrypter(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ct_buf := make([]byte, len(plaintext)+32)

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := ct_buf[0:12]
	if _, err := io.ReadFull(ct.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(ct_buf[12:12], nonce, plaintext, nil)

	return ct_buf[:12+len(ciphertext)], nil
}

func AesGcmDecrypter(key []byte, ciphertext []byte) ([]byte, error) {
	nonce := ciphertext[0:12]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ct := ciphertext[12:]
	pt, _ := aesgcm.Open(ct[:0], nonce, ct, nil)
	if err != nil {
		return nil, err
	}

	return pt, nil
}
