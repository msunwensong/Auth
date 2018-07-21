package secure_auth

import (
	"fmt"
	"testing"
)

//测试整个流程
func TestSecureFlow(t *testing.T) {
	/*                  认证部分 start  				*/
	//var auth Auth //创建auth（认证对象）
	auth := Auth{}
	//1.认证前-需要生成ckey、【sign、时间戳、id】
	err := auth.GeneratorCkeyAndSign("ae:op:aa:kk") //注意这是mac
	if err != nil {
		t.Error("GeneratorCkeyAndSign error !!!", err)
		return
	}
	fmt.Println("time:", auth.SCommResult.Timestamp, "sign:", auth.SCommResult.Sign)

	/*
	   2.认证前-发送请求，让服务端分配的token,skey
	   (url带上 id、auth.Timestamp、auth.SCommResult.Sign参数)
	*/

	//sign 、status、Timestamp、data 参数是server给的
	smp := SCommParam{Status: 0, Sign: "111", Data: []byte{1, 2, 3}, Timestamp: 1212}
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
