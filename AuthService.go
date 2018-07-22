package secure_auth

import (
	"auth/utils"
	"bytes"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/tidwall/gjson"
)

const CKEY_NUM = 6719

//定义认证类型
type Auth struct {
	SCommResult
	ckey    string //ckey(自己使用)
	Id      string //MD5(mac)
	Token   string //Token 服务端分配
	Skey    string //Skey  服务端分配
	ProbeId string //探针Id
}

//生成sign、timestamp。 参数mac地址
func (a *Auth) GeneratorCkeyAndSign(mac string) error {
	//0 id  注意这是md5(mac)
	a.Id = utils.Md5([]byte(mac))
	a.SCommResult.Timestamp = time.Now().Unix()
	//1.生成ckey=MD5(probeId+(Long)timestamp/6719)
	a.ProbeId = utils.GetProbeId(a.Id)
	buf := &bytes.Buffer{}
	buf.WriteString(a.ProbeId)                                                   //id
	buf.WriteString(strconv.FormatInt((a.SCommResult.Timestamp / CKEY_NUM), 10)) //timestamp
	a.ckey = utils.Md5([]byte(buf.String()))
	//2.计算签名(sign=sha256(id+timestamp+ckey))
	buf.Reset()                                         //buf重置
	buf.WriteString(a.Id)                               //id
	buf.WriteString(strconv.FormatInt(a.Timestamp, 10)) //timestamp
	buf.WriteString(a.ckey)                             //ckey
	a.SCommResult.Sign = utils.Sha256([]byte(buf.String()))
	return nil
}

/*

1.签名验证sign=sha256(data+timestamp+status+ckey)
		2.用AES密码ckey解密数据
		3.得到token、过期时间、服务端生成的skey
		{
			status:0, 0-正常 1-异常
			"data":{
			"skey":"ssss", --明文(服务生成)
			"token":"xxxx",
			"expire":123344
			},
			"timestamp":15290011,
			"sign":123 sign=sha256(data+timestamp+status+ckey)
		}
*/

//获取服务端分配的token
func (a *Auth) GetTokenAndSkey(smp *SCommParam) error {
	//0.校验服务器是否成功
	jsonStr := string(smp.Data)
	result := gjson.Get(jsonStr, "status")
	if result.Int() != 0 {
		return errors.New("status not equal zero ")
	}

	//1.签名验证sign=sha256(data+timestamp+status+ckey)
	buf := &bytes.Buffer{}
	for _, val := range []string{"data", "timestamp", "status"} {
		result = gjson.Get(jsonStr, val)
		buf.WriteString(result.String())
	}
	buf.WriteString(a.ckey) //ckey
	sign := utils.Sha256([]byte(buf.String()))
	result = gjson.Get(jsonStr, "sign")
	if sign != result.String() {
		return errors.New("sign not equal")
	}
	//2.用AES密码ckey解密数据
	result = gjson.Get(jsonStr, "data")
	//base64解码
	decode := utils.Base64Decode(result.String())
	//aes解密
	ckeyBytes, cErr := hex.DecodeString(a.ckey)
	if cErr != nil {
		return cErr
	}
	tmp, err := utils.AESCBCDecrypter(ckeyBytes, decode)
	if err != nil {
		return err
	}
	jsonStr = string(tmp[:])
	//3.得到token、过期时间、服务端生成的skey
	result = gjson.Get(jsonStr, "skey")
	a.Skey = result.String()
	result = gjson.Get(jsonStr, "token")
	a.Token = result.String()
	return nil
}
