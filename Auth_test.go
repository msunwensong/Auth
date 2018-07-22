package secure_auth

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"
)

//测试整个流程
func TestSecureFlow(t *testing.T) {

	/*                  认证部分 start  				*/
	auth := Auth{}
	//1.认证前-需要生成ckey、【sign、时间戳、id】
	err := auth.GeneratorCkeyAndSign("ae:op:aa:kk") //注意这是mac
	if err != nil {
		t.Error("GeneratorCkeyAndSign error !!!", err)
		return
	}
	fmt.Println("id:", auth.Id, "time:", auth.Timestamp, "sign:", auth.Sign)

	//2.认证前-发送请求，让服务端分配的token,skey(url带上 id、auth.Timestamp、auth.SCommResult.Sign参数)
	data := sendGet(auth.Id, auth.Timestamp, auth.Sign)

	smp := SCommParam{Data: data}
	terr := auth.GetTokenAndSkey(&smp)
	if terr != nil {
		fmt.Println("GetTokenAndSkey error ", terr)
		return
	}
	/*                  认证部分 end  				*/

	//3.通信操作
	comm := Communication{} //实例化comm(通信对象)
	//调用加密方法  进行数据加密
	comm.init("1", "2", "3")
	eErr := comm.EncryptionData([]byte{1}) //注意这是probeId md5(md5(mac)+6101)
	if eErr != nil {
		fmt.Println("EncryptionData error ", eErr)
		return
	}
	//打印加密结果
	fmt.Println(comm.SCommResult)

	//4.
	smp.Data = []byte{0, 0, 0} //服务端响应数据
	smp.Status = 0             //服务端响应的错误码
	smp.Timestamp = 1111       //服务端的时间戳
	smp.Sign = "1331"          //服务端的sign

	dErr := comm.DecryptionData(&smp)
	if dErr != nil {
		fmt.Println("DecryptionData error ", dErr)
		return
	}
	//打印解密结果
	fmt.Println(comm)
}

func sendGet(id string, t int64, sign string) []byte {
	url := "http://localhost:8080/gw-auth/certification/auth?id=" + id + "&timestamp=" + strconv.FormatInt(t, 10) + "&sign=" + sign
	resp, _ := http.Get(url)
	p := make([]byte, 2048)
	n, _ := resp.Body.Read(p)
	fmt.Println(string(p[:n]))
	return p[:n]
}
