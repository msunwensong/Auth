package secure_auth

import (
	"auth/utils"
	"bytes"
	"encoding/hex"
	"errors"
	"strconv"
	"time"
)

//定义认证类型
type Communication struct {
	SCommResult
	token   string //Token 服务端分配(自己使用)
	skey    string //Skey  服务端分配(自己使用)
	probeId string //探针ID (自己使用)
}

func (c *Communication) Init(skey, token, probeId string) {
	c.skey = skey
	c.token = token
	c.probeId = probeId //两次mad5之后的值
}

//生成sign、ckey。 参数 id
func (c *Communication) EncryptionData(data []byte) error {
	//1.使用skey加密请求数据
	skeyBytes, sErr := hex.DecodeString(c.skey)
	if sErr != nil {
		return sErr
	}
	tmp, err := utils.AESCBCEncrypter(skeyBytes, data)
	if err != nil {
		return err
	}
	c.Data = tmp //aes加密之后数据
	c.Timestamp = time.Now().Unix()
	//2.计算签名(sign=sha256(data+timestamp+token+probeId+skey)
	buf := make([]byte, 0)
	buf = append(buf, c.Data...)
	buf = append(buf, []byte(strconv.FormatInt(c.Timestamp, 10))...)
	buf = append(buf, []byte(c.token)...)
	buf = append(buf, []byte(c.probeId)...)
	buf = append(buf, []byte(c.skey)...)
	c.Sign = utils.Sha256(buf)
	return nil
}

//
func (c *Communication) DecryptionData(smp *SCommParam) error {
	//1.签名验证sign=sha256(data+timestamp+status+skey)
	dataBuf := make([]byte, 0)
	dataBuf = append(dataBuf, smp.Data...)

	buf := &bytes.Buffer{}
	buf.WriteString(strconv.FormatInt(smp.Timestamp, 10)) //timestamp
	buf.WriteString(string(smp.Status))                   //status
	buf.WriteString(c.skey)                               //skey
	dataBuf = append(dataBuf, []byte(buf.String())...)
	sign := utils.Sha256(dataBuf)
	if sign != smp.Sign {
		return errors.New("sign not equal")
	}
	//2.用AES密码skey解密数据
	//aes解密
	skeyBytes, sErr := hex.DecodeString(c.skey)
	if sErr != nil {
		return sErr
	}
	tmp, err := utils.AESCBCDecrypter(skeyBytes, smp.Data)
	if err != nil {
		return err
	}
	c.Data = tmp //用明文替换密文
	return nil
}
