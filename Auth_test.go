package secure_auth

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"
)

//测试整个流程
func TestSecureFlow(t *testing.T) {
	// b:=[]byte{'-90', '-64', '-123', '59', '-81', '47', '-101', '115', '-118', '-6', '-101', '-68',' -31', '-100', '-85', '39', '87', '-46', '-122', '-77', '-101', '34', '-9', '51', '-52', '-103', '-32', '111', '-121', '-100', '-2', '118'}

	//en := utils.Base64Encode([]byte{-90, -64, -123, 59, -81, 47, -101, 115, -118, -6, -101, -68, -31, -100, -85, 39, 87, -46, -122, -77, -101, 34, -9, 51, -52, -103, -32, 111, -121, -100, -2, 118})
	//	aaa := "psCFO68vm3OK+pu84ZyrJwSMkCjYa0hL4E6qMGfjZm5XNLUEBowC+LRaXlTDySmUarudoPIFE4yAuP3zig7QNlTy/xxDKycgpOZEA+fo7sVO25k2/M+++az53xK0uBSvM3fqz4LT8uOhgm7NI9/Pr/okfiU5FnVExByRCuxduBAS4tR5EOavePh797rIZlkG9un45h6lmPouUxZFI2agI1YhR5g2hDMfyYCzEFwH9TJSl5ZZawFNA7yhUGRyJyCw+R0F1lsy73YtSwDGSuViFBji6DqIoaQbsBeXOMDZfD4="
	//	fmt.Println(utils.Base64Decode(strings.ToUpper(aaa)))

	/*                  认证部分 start  				*/
	auth := Auth{}
	//1.认证前-需要生成ckey、【sign、时间戳、id】
	err := auth.GeneratorCkeyAndSign("ae:op:aa:kk") //注意这是mac
	if err != nil {
		t.Error("GeneratorCkeyAndSign error !!!", err)
		return
	}
	fmt.Println("id:", auth.Id, "time:", auth.Timestamp, "sign:", auth.Sign)

	data := sendGet(auth.Id, auth.Timestamp, auth.Sign)

	/*
	   2.认证前-发送请求，让服务端分配的token,skey
	   (url带上 id、auth.Timestamp、auth.SCommResult.Sign参数)
	*/
	//sign 、status、Timestamp、data 参数是server给的
	smp := SCommParam{Status: 0, Sign: "111", Data: data, Timestamp: 1212}
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
	return p
}
