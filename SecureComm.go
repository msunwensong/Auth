package secure_auth

//输出结果类型
type SCommResult struct {
	Sign      string //数据签名
	Timestamp int64  //时间戳
	Data      []byte //加密数据
}

//输入结果类型
type SCommParam struct {
	Status    byte   //状态码
	Data      []byte //原始数据
	Timestamp int64  //时间戳
	Sign      string //数据签名
}
