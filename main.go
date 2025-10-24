// main.go - IPv6 零信任快传网盘（官方 QUIC 新路径版）
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"         // Web 框架
	"github.com/quic-go/quic-go/http3" // 官方 QUIC/HTTP3（注意路径）
	"github.com/skip2/go-qrcode"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// ========== 1. 命令行参数 ==========
var (
	maxMemoryMB = flag.Int("max-mem", 500, "全局内存池上限(MB)")
	maxSizeMB   = flag.Int("max-size", 50, "单文件大小上限(MB)")
	ttlMinutes  = flag.Int("ttl", 10, "文件存活时间(分钟)")
	maxTimes    = flag.Int("times", 3, "最大下载次数")
	portQUIC    = flag.String("quic", ":443", "QUIC/HTTP3 端口")
	portTCP     = flag.String("tcp", ":8080", "TCP 回退端口")
)

// ========== 2. 内存实体 ==========
type fileMeta struct {
	data     []byte    // 文件内容
	fileName string    // 文件名
	size     int64     //文件大小
	left     int32     // 剩余下载次数
	expAt    time.Time // 到期即焚
}

var (
	store     sync.Map // 并发 map[string]*fileMeta
	currentMB int64    // 当前内存占用（字节）
	memMutex  sync.Mutex
)

// ========== 3. 入口 ==========
func main() {
	flag.Parse()
	//gin.SetMode(gin.ReleaseMode)
	gin.SetMode(gin.DebugMode)
	r := gin.New()
	r.Use(gin.Recovery())           // 捕获 panic
	r.Static("/static", "./static") // 单页前端
	r.GET("/", func(c *gin.Context) { c.File("./static/index.html") })
	r.POST("/up", uploadHandler)       // 上传
	r.GET("/d/:hash", downloadHandler) // 下载（立即焚毁）

	// 1. 加载 TLS 证书（QUIC/HTTP3 必须使用 TLS）
	certFile, keyFile := selfSign()
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		panic("Failed to load certificate: " + err.Error())
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"h3"}, // HTTP/3 ALPN
	}

	// 2. 组装 http3.Server（注意是结构体，不是包级函数）
	h3Server := &http3.Server{
		Addr:      *portQUIC, // 使用命令行参数指定的端口
		TLSConfig: tlsConfig,
		Handler:   r, // gin.Engine 实现了 http.Handler
	}

	// 3. 启动 HTTP/3 服务（在单独的 goroutine 中）
	go func() {
		fmt.Println("QUIC listening on", *portQUIC) // ← 新增
		if err := h3Server.ListenAndServe(); err != nil {
			panic("QUIC fail: " + err.Error())
		}
	}()

	// TCP 双栈回退
	//r.RunTLS("[::]:8080", "cert.pem", "key.pem")
	if err := r.Run("[::]" + *portTCP); err != nil {
		panic("TCP start fail: " + err.Error())
	}
}

// ========== 4. 上传 ==========
func uploadHandler(c *gin.Context) {
	// 从请求中获取上传的文件
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.String(http.StatusBadRequest, "Missing file")
		return
	}
	defer file.Close()

	// 检查文件大小是否超过限制
	size := header.Size
	if size > int64(*maxSizeMB)<<20 {
		c.String(http.StatusRequestEntityTooLarge, "File too large")
		return
	}

	// 检查内存池是否已满
	memMutex.Lock()
	if currentMB+size > int64(*maxMemoryMB)<<20 {
		memMutex.Unlock()
		c.String(http.StatusInsufficientStorage, "Memory full")
		return
	}
	currentMB += size
	memMutex.Unlock()

	// 读取文件内容并计算哈希值

	// 读取上传的文件内容到内存中
	data, err := io.ReadAll(file)
	if err != nil {
		// 如果读取失败，释放已增加的内存计数并返回错误
		log.Printf("Failed to read file: %v", err)
		memMutex.Lock()
		currentMB -= size
		memMutex.Unlock()
		c.String(http.StatusInternalServerError, "Failed to read file")
		return
	}

	// 使用SHA256算法计算文件内容的哈希值，作为文件的唯一标识符
	hash := sha256.Sum256(data)
	hashStr := hex.EncodeToString(hash[:])

	// 创建文件元数据结构，包含文件数据、文件名、剩余下载次数和过期时间
	meta := &fileMeta{
		data:     data,
		fileName: header.Filename,                                          // 添加文件名
		size:     size,                                                     //文件大小
		left:     int32(*maxTimes),                                         // 设置最大下载次数
		expAt:    time.Now().Add(time.Duration(*ttlMinutes) * time.Minute), // 设置过期时间
	}
	// 将文件元数据存储到并发安全的map中，以哈希值作为key
	store.Store(hashStr, meta)

	// 从请求中提取主机地址，并构造下载链接
	host, _, _ := net.SplitHostPort(c.Request.Host)
	// 构造下载链接，使用TCP回退端口
	link := "http://[" + host + "]:8080/d/" + hashStr
	// 生成下载链接的二维码图片
	png, err := qrcode.Encode(link, qrcode.Medium, 256)
	if err != nil {
		// 如果二维码生成失败，记录错误但不影响主要功能
		fmt.Println("Failed to generate QR code:", err)
	}

	// 返回JSON响应，包含下载链接和二维码
	//新增文件大小，文件名，文件格式
	c.JSON(http.StatusOK, gin.H{
		"file_name": header.Filename,
		"file_size": size,
		"link":      link,
		"qr":        "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
}

// ========== 5. 下载 + 焚毁 ==========
func downloadHandler(c *gin.Context) {
	// 从URL参数中获取文件hash
	hash := c.Param("hash")
	log.Println("访问的hash:", hash)

	// 从存储中查找对应hash的文件元数据
	v, ok := store.Load(hash)
	if !ok {
		// 如果找不到对应文件，返回404错误
		c.String(http.StatusNotFound, "Gone")
		return
	}

	// 类型断言获取文件元数据
	meta := v.(*fileMeta)

	// 检查文件是否已过期
	if time.Now().After(meta.expAt) {
		// 如果过期则从存储中删除并返回过期信息
		store.Delete(hash)
		c.String(http.StatusNotFound, "Expired")
		return
	}

	// 减少文件剩余下载次数
	meta.left--
	if meta.left <= 0 {
		// 如果下载次数用完，则从存储中删除文件
		store.Delete(hash)
	}

	// 更新内存使用统计
	memMutex.Lock()
	currentMB -= int64(len(meta.data))
	memMutex.Unlock()

	//将文件名保存到头部
	encodedName := url.QueryEscape(meta.fileName)
	c.Header("Content-Disposition",
		`attachment; filename*=UTF-8''`+encodedName)
	// 返回文件数据给客户端
	c.Data(http.StatusOK, "application/octet-stream", meta.data)
}

// ========== 6. 自签 TLS（HTTP3 必需） ==========
func selfSign() (certFile, keyFile string) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"FireShare"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IPAddresses:  []net.IP{net.IPv6loopback, net.IPv6zero},
		DNSNames:     []string{"localhost"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	certOut, _ := os.Create("cert.pem")
	err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err != nil {
		return "", ""
	}
	err = certOut.Close()
	if err != nil {
		return "", ""
	}
	keyOut, _ := os.Create("key.pem")
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err != nil {
		return "", ""
	}
	err = keyOut.Close()
	if err != nil {
		return "", ""
	}
	return "cert.pem", "key.pem"
}
