//密码
//只可修复问题 不可更改算法

//$ go build -ldflags "-s -w" aaa-pass.go

//使用方法及算法前缀校对
//$ aaa-pass i
//aaa-pass(i) == 2e.....

//如果出错，那是需要 $ aaa-key 命令存在

//诸如百度，限制长度为6~14个字符，所以密码不宜超过14个字符，最佳13-14个字符
//如果密码要求包含特殊符号，那么在结尾手动加 ;

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"strconv"
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
	rf := r.FindStringSubmatch(getCmdOutput("aaa-key aaa-pass"))
	if len(rf) == 1 {
		aaaPassKey := rf[0]
		//fmt.Printf("%s\n", aaaPassKey)
		//$ aaa-key aaa-pass

		l := 13
		lc := []byte(hashSha256(aaaPassKey + seed))
		lcd := anyToDecimal(string(lc[:1]), 16)
		if lcd%2 == 0 {
			l = 14
		}

		var pass []byte
		var i int = 1

		//必须同时包含数字、小写字母、大写字母
	PWDGEN:
		pass = []byte{}
		for j := 0; j < l; j++ {
			random := []byte(hashSha256(string(i) + aaaPassKey + string(j) + seed))
			char := []byte(decimalToAny(anyToDecimal(string(random[:8]), 16), 62))
			pass = append(pass, char[len(char)-1])
		}

		m1, _ := regexp.MatchString("[0-9]+", string(pass))
		m2, _ := regexp.MatchString("[a-z]+", string(pass))
		m3, _ := regexp.MatchString("[A-Z]+", string(pass))
		if !m1 || !m2 || !m3 {
			i++
			goto PWDGEN
		}

		fmt.Printf("aaa-pass(%s) == %s\n", seed, string(pass))
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

//10进制转任意进制
func decimalToAny(num, n int) string {
	new_num_str := ""
	var remainder int
	var remainder_string string
	for num != 0 {
		remainder = num % n
		if 76 > remainder && remainder > 9 {
			remainder_string = tenToAny[remainder]
		} else {
			remainder_string = strconv.Itoa(remainder)
		}
		new_num_str = remainder_string + new_num_str
		num = num / n
	}
	return new_num_str
}

//任意进制转10进制
func anyToDecimal(num string, n int) int {
	var new_num float64
	new_num = 0.0
	nNum := len(strings.Split(num, "")) - 1
	for _, value := range strings.Split(num, "") {
		tmp := float64(findKey(value))
		if tmp != -1 {
			new_num = new_num + tmp*math.Pow(float64(n), float64(nNum))
			nNum = nNum - 1
		} else {
			break
		}
	}
	return int(new_num)
}

//map根据value找key
func findKey(in string) int {
	result := -1
	for k, v := range tenToAny {
		if in == v {
			result = k
		}
	}
	return result
}

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
