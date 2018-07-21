package secure_auth

import (
	"auth/utils"
	"fmt"
	"time"
)

//定义认证类型
type Auth struct {
	SCommResult
	ckey  string //ckey(自己使用)
	Id    string //MD5(mac)
	Token string //Token 服务端分配
	Skey  string //Skey  服务端分配
}

//生成sign、timestamp。 参数mac地址
func (a *Auth) GeneratorCkeyAndSign(mac string) error {
	//0 id  注意这是md5(mac)
	a.Id = utils.Md5([]byte(mac))
	a.SCommResult.Timestamp = time.Now().Unix()
	//1.生成ckey=MD5(probeId+(Long)timestamp/6719)
	probeId := utils.GetProbeId(a.Id, a.SCommResult.Timestamp)
	tmp := probeId + (a.SCommResult.Timestamp / 6719)
	a.ckey = utils.Md5([]byte(tmp))
	//2.计算签名(sign=sha256(id+timestamp+ckey))
	sn := append([])
	a.SCommResult.Sign = utils.Sha256(sn)
	return nil
}

//获取服务端分配的token
func (a *Auth) GetTokenAndSkey(smp *SCommParam) error {
	//1.签名验证sign=sha256(data+timestamp+status+ckey)
	//2.用AES密码ckey解密数据
	//3.得到token、过期时间、服务端生成的skey
	fmt.Println(*smp)
	a.Skey = "ssss"
	a.Token = "ttttttt"
	return nil
}
