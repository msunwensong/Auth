package secure_auth

import (
	"time"
)

//定义认证类型
type Communication struct {
	SCommResult
	token   string //Token 服务端分配(自己使用)
	skey    string //Skey  服务端分配(自己使用)
	probeId string //探针ID (自己使用)
}

func (c *Communication) Init(skey, token, mac string) {
	c.skey = skey
	c.token = token
	c.probeId = mac //两次mad5之后的值
}

//生成sign、ckey。 参数 id
func (c *Communication) EncryptionData(data []byte) error {
	c.Data = data
	c.Timestamp = time.Now().Unix()
	c.Sign = "111111"
	return nil
}

//
func (c *Communication) DecryptionData(smp *SCommParam) error {
	c.Data = []byte{1, 1, 1, 1, 1}
	return nil
}
