package secure_auth

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"testing"
)

//测试整个流程
func TestSecureFlow(t *testing.T) {

	/*                  认证部分 start  				*/
	mac := "ae:op:aa:kk" //光猫的mac地址
	auth := Auth{}
	//1.认证前-需要生成ckey、【sign、时间戳、id】
	err := auth.GeneratorCkeyAndSign(mac) //注意这是mac
	if err != nil {
		t.Error("GeneratorCkeyAndSign error !!!", err)
		return
	}
	fmt.Println("【认证】待发送服务端数据", "id:", auth.Id, "time:", auth.Timestamp, "sign:", auth.Sign)

	//2.认证前-发送请求，让服务端分配的token,skey(url带上 id、auth.Timestamp、auth.SCommResult.Sign参数)
	data := sendGet(auth.Id, auth.Timestamp, auth.Sign)
	fmt.Println("【认证】服务端响应数据:", string(data))

	smp := SCommParam{Data: data}
	terr := auth.GetTokenAndSkey(&smp)
	if terr != nil {
		fmt.Println("GetTokenAndSkey error ", terr)
	}
	/*                  认证部分 end  				*/

	//3.通信操作
	comm := Communication{} //实例化comm(通信对象)
	fmt.Println("【认证】得到服务端分配token:", auth.Token, "skey", auth.Skey)
	//调用加密方法  进行数据加密
	comm.Init(auth.Skey, auth.Token, auth.ProbeId)
	eErr := comm.EncryptionData([]byte("hello")) //注意这是probeId md5(md5(mac)+6101)
	if eErr != nil {
		fmt.Println("EncryptionData error ", eErr)
		return
	}
	fmt.Println("【通信】待发送到服务端sign:", comm.Sign, "probeId:", auth.ProbeId)
	resData, times, s, sign := sendPost(&comm.SCommResult, auth.ProbeId, auth.Token)
	//4.解密操作
	smp.Data = resData                                 //服务端响应数据
	smp.Status = s[0]                                  //服务端状态吗
	smp.Timestamp, _ = strconv.ParseInt(times, 10, 64) //服务端的时间戳
	smp.Sign = sign                                    //服务端的sign

	dErr := comm.DecryptionData(&smp)
	if dErr != nil {
		fmt.Println("DecryptionData error ", dErr)
		return
	}
	//打印解密结果
	fmt.Println("【通信】解密结果", string(comm.Data))
}
func sendPost(cmr *SCommResult, probeId, token string) ([]byte, string, string, string) {
	client := &http.Client{}
	//生成要访问的url
	url := "http://localhost:8080/gw-auth/communication"
	//提交请求
	body := bytes.NewReader(cmr.Data)
	reqest, err := http.NewRequest("POST", url, body)

	//增加header选项
	reqest.Header.Add("Timestamp", strconv.FormatInt(cmr.Timestamp, 10))
	reqest.Header.Add("Sign", cmr.Sign)
	reqest.Header.Add("ProbeId", probeId)
	reqest.Header.Add("Token", token)

	if err != nil {
		panic(err)
	}
	//处理返回结果
	response, _ := client.Do(reqest)

	p := make([]byte, 2048)
	n, _ := response.Body.Read(p)
	defer response.Body.Close()

	return p[:n], response.Header.Get("Timestamp"), response.Header.Get("Status"), response.Header.Get("Sign")
}

func sendGet(id string, t int64, sign string) []byte {
	url := "http://localhost:8080/gw-auth/certification/auth?id=" + id + "&timestamp=" + strconv.FormatInt(t, 10) + "&sign=" + sign
	//url := "http://124.95.165.175:8888/gw-auth/certification/auth?id=" + id + "&timestamp=" + strconv.FormatInt(t, 10) + "&sign=" + sign
	resp, _ := http.Get(url)
	p := make([]byte, 2048)
	n, _ := resp.Body.Read(p)
	return p[:n]
}
