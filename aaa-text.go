//密文
//只可修复问题 不可更改算法

//$ go build -ldflags "-s -w" aaa-text.go

//使用方法
//$ aaa-text "this is a test"
//ABC123...
//每次加密各不相同（避免多次重复，痕迹被人追踪）
//$ aaa-text ABC123...
//this is a test

//如果出错，那是需要 $ aaa-key 命令存在

//进阶：

//$ aaa-text ~/原件.jpg > ~/密文.txt
//$ aaa-text ~/密文.txt > ~/原件.jpg

//$ aaa-text ~/原件.md > ~/密文.txt
//$ aaa-text ~/密文.txt > ~/原件.md

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"path"
	"strings"
	"time"
)

func main() {
	if len(os.Args) == 2 {
		var r = regexp.MustCompile(`[A-F0-9]{64}`)
		rf := r.FindStringSubmatch(getCmdOutput("aaa-key aaa-text"))
		if len(rf) == 1 {
			aaaTextKey := rf[0]
			//fmt.Printf("%s\n", aaaTextKey)
			//$ aaa-key aaa-text

			input := os.Args[1]
			isFile := fileExists(input)

			if isFile {
				f, _ := os.OpenFile(input, os.O_RDONLY, 0600)
				defer f.Close()

				c, _ := ioutil.ReadAll(f)
				input = string(c)
			}

			//如果解密，去除中间换行，去除两端空白（尤其是文件中可能存在）
			inputTrim := strings.Trim(strings.Replace(input, "\n", "", -1), " \n\t\r")
			//如果文件，去除文件名的部分
			if isFile {
				//纵如favicon.ico，1KB都有2000+字符，何况72（也就是：一行+）
				var r2 = regexp.MustCompile(`[A-F0-9]{72,}`)
				rf2 := r2.FindStringSubmatch(inputTrim)
				if len(rf2) == 1 {
					inputTrim = rf2[0]
				}
			}

			//解密
			match, _ := regexp.MatchString("[0-9A-F]{9,}", inputTrim)
			if match {
				if len(inputTrim) > 12 && strings.ToUpper(s256(aaaTextKey + inputTrim[0:6]))[0:6] == inputTrim[6:12] {
					//应该解密
					seed := inputTrim[0:12]

					kiHash := []byte(s256(aaaTextKey + seed))
					key := kiHash[:32] //AES-256-CBC
					iv := kiHash[32:48]

					fmt.Printf("%s\n", aescbcDecrypt([]byte(inputTrim[12:]), key, iv))
					return
				}
			}

			//加密

			//生成一个基于时间的种子
			//神奇的 2006-01-02 15:04:05 -0700
			//其实人家这个日期是有意义的：
			//2006-01-02T15:04:05Z07:00
			//1 2 3 4 5 6 7
			//月 日 时 分 秒 年 时 区
			//time.Now().Format("2006-01-02 15:04:05 -0700")
			hash := s256(aaaTextKey + time.Now().Format("20060102150405"))
			// fmt.Printf("%s\n", time.Now().Format("20060102150405")) //20191207150716
			six := strings.ToUpper(hash[0:6])
			seed := strings.ToUpper(six + s256(aaaTextKey + six)[0:6]) //取12位做种子

			kiHash := []byte(s256(aaaTextKey + seed))
			key := kiHash[:32] //AES-256-CBC
			iv := kiHash[32:48]
			encode := string(aescbcEncrypt([]byte(input), key, iv))

			output := seed + encode
			if isFile {
				wrapWidth := 72
				//implode
				output = strings.Join(SplitSubN(output, wrapWidth), "\n")
			}

			//如果文件，增加文件名的部分
			if isFile {
				file := path.Base(os.Args[1])
				head := file + ":\n"
				output = head + output
			}

			fmt.Printf("%s\n", output)
		}
	}
}

//按长度拆分字符串
func SplitSubN(s string, n int) []string {
	sub := ""
	subs := []string{}

	runes := bytes.Runes([]byte(s))
	l := len(runes)
	for i, r := range runes {
		sub = sub + string(r)
		if (i + 1) % n == 0 {
			subs = append(subs, sub)
			sub = ""
		} else if (i + 1) == l {
			subs = append(subs, sub)
		}
	}

	return subs
}

//文件是否存在
func fileExists(path string) bool {
	_, e := os.Stat(path)
	if e != nil {
		if os.IsExist(e) {
			return true
		}
		return false
	}
	return true
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
func s256(str string) string {
	s256 := sha256.New()
	s256.Write([]byte(str))
	result := hex.EncodeToString(s256.Sum(nil))

	return result
}

//golang 实现 AES-128-CBC AES-192-CBC AES-256-CBC 加密解密算法
//key 16 位就是 AES-128-CBC ； key 24 位就是 AES-192-CBC ； key 32 位就是 AES-256-CBC
//iv 固定长度 16 位

func aescbcEncrypt(sourced []byte, key []byte, iv []byte) []byte {
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()
	sourced = aescbcPkcs7Padding(sourced, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(sourced))
	blockMode.CryptBlocks(crypted, sourced)
	return []byte(strings.ToUpper(aescbcBin2hex(string(crypted))))
}
func aescbcDecrypt(crypted []byte, key []byte, iv []byte) []byte {
	crypted = []byte(aescbcHex2bin(string(crypted)))
	block, _ := aes.NewCipher(key)
	blockMode := cipher.NewCBCDecrypter(block, iv)
	sourced := make([]byte, len(crypted))
	blockMode.CryptBlocks(sourced, crypted)
	sourced = aescbcPkcs7UnPadding(sourced)
	return sourced
}

func aescbcPkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
func aescbcPkcs7UnPadding(sourced []byte) []byte {
	length := len(sourced)
	unpadding := int(sourced[length-1])
	if length-unpadding < 0 { //避免出错：panic: runtime error: slice bounds out of range
		return []byte{}
	}
	return sourced[:(length - unpadding)]
}

func aescbcBin2hex(raw string) string {
	return hex.EncodeToString([]byte(raw))
}
func aescbcHex2bin(raw string) string {
	result, _ := hex.DecodeString(raw)
	return string(result)
}
