//密码
//只可修复问题 不可更改算法

//$ go build -ldflags "-s -w" aaa-pass7z.go

//使用方法及算法前缀校对
//$ aaa-pass7z i
//aaa-pass7z(i) == 10...

//如果出错，那是需要 $ aaa-key 命令存在

//诸如百度，限制长度为6~14个字符，所以密码不宜超过14个字符，最佳13-14个字符
//如果密码要求包含特殊符号，那么在结尾手动加 ;

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

func main() {
	var seed string
	if len(os.Args) == 2 {
		seed = os.Args[1]
	} else {
		//神奇的 2006-01-02 15:04:05 -0700
		//其实人家这个日期是有意义的：
		//2006-01-02T15:04:05Z07:00
		//1 2 3 4 5 6 7
		//月 日 时 分 秒 年 时 区
		//seed = time.Now().Format("2006-01-02 15:04:05 -0700")
		seed = time.Now().Format("20060102150405")
		// fmt.Printf("%s\n", time.Now().Format("20060102150405")) //20191207150716
	}

	var r = regexp.MustCompile(`[A-F0-9]{64}`)
	rf := r.FindStringSubmatch(getCmdOutput("aaa-key aaa-pass7z"))
	if len(rf) == 1 {
		aaaPassKey := rf[0]
		//fmt.Printf("%s\n", aaaPassKey)
		//$ aaa-key aaa-pass7z

		//7z格式支持256位键钥AES算法加密。键钥则由用户提供的口令（密码短语）进行SHA-256 hash算法得到。SHA-256执行2的18 (262144)次（这种技术称为密钥延伸），使得对口令的暴力解码更加困难。
		//密钥延伸：通过增加尝试每个可能密码所需的时间和空间（如果可能）资源，有效阻止蛮力攻击（暴力破解）
		//SHA256是 `64位的16进制数`
		//所以使用 `64位的16进制数`
		//就能达到 `满载密码` 效果：自行搜索`一个压缩包 可以存在两个正确的密码`
		mima := strings.ToUpper(hashSha256(aaaPassKey + seed))
		fmt.Printf("aaa-pass7z(%s) == %s\n", seed, mima)
	}
}

var tenToAny map[int]string = map[int]string{
	0:  "0",
	1:  "1",
	2:  "2",
	3:  "3",
	4:  "4",
	5:  "5",
	6:  "6",
	7:  "7",
	8:  "8",
	9:  "9",
	10: "a",
	11: "b",
	12: "c",
	13: "d",
	14: "e",
	15: "f",
	16: "g",
	17: "h",
	18: "i",
	19: "j",
	20: "k",
	21: "l",
	22: "m",
	23: "n",
	24: "o",
	25: "p",
	26: "q",
	27: "r",
	28: "s",
	29: "t",
	30: "u",
	31: "v",
	32: "w",
	33: "x",
	34: "y",
	35: "z",
	36: "A",
	37: "B",
	38: "C",
	39: "D",
	40: "E",
	41: "F",
	42: "G",
	43: "H",
	44: "I",
	45: "J",
	46: "K",
	47: "L",
	48: "M",
	49: "N",
	50: "O",
	51: "P",
	52: "Q",
	53: "R",
	54: "S",
	55: "T",
	56: "U",
	57: "V",
	58: "W",
	59: "X",
	60: "Y",
	61: "Z"}

//获得命令输出
func getCmdOutput(command string) string {
	process := exec.Command("/bin/sh", "-c", command)
	out, err := process.Output()
	if err != nil {
		panic(err.Error())
	}
	return string(out)
}

//sha256加密
func hashSha256(str string) string {
	hashSha256 := sha256.New()
	hashSha256.Write([]byte(str))
	result := hex.EncodeToString(hashSha256.Sum(nil))

	return result
}
