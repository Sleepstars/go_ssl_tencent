package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"
)

// Config 结构体表示 config.yaml 文件的结构
type Config struct {
	SecretId  string `yaml:"secret_id"`
	SecretKey string `yaml:"secret_key"`
	CertPaths struct {
		FullChainPem string `yaml:"fullchain_pem"`
		PrivKeyPem   string `yaml:"privkey_pem"`
	} `yaml:"cert_paths"`
	ValidateCertApi  string   `yaml:"validate_cert_api"`
	ServicesToDeploy []string `yaml:"services_to_deploy"`
	Log              struct {
		Enable     bool   `yaml:"enable"`
		Path       string `yaml:"path"`
		MaxSize    int    `yaml:"max_size"`    // 单个日志文件最大大小（MB）
		MaxBackups int    `yaml:"max_backups"` // 保留的旧日志文件数量
		MaxAge     int    `yaml:"max_age"`     // 旧日志文件保留天数
		Compress   bool   `yaml:"compress"`    // 是否压缩旧日志文件
	} `yaml:"log"`
}

type CertState struct {
	Hash      string    `yaml:"hash"`
	LastCheck time.Time `yaml:"last_check"`
}

// CustomError 自定义错误类型
type CustomError struct {
	Op      string // 操作名称
	Err     error  // 原始错误
	Message string // 错误信息
}

func (e *CustomError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Op, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Op, e.Message)
}

// 读取 config.yaml 文件
func loadConfig(filePath string) (*Config, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// 计算文件的SHA256哈希值
func calculateFileHash(filepath string) (string, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// 读取证书内容
func loadCertificates(fullChainPath, privKeyPath string) (string, string, error) {
	fullChain, err := ioutil.ReadFile(fullChainPath)
	if err != nil {
		return "", "", err
	}

	privKey, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return "", "", err
	}

	return string(fullChain), string(privKey), nil
}

// 上传证书到腾讯云
func uploadCertificate(client *ssl.Client, certContent, keyContent string) error {
	request := ssl.NewUploadCertificateRequest()
	request.CertificatePublicKey = common.StringPtr(certContent)
	request.CertificatePrivateKey = common.StringPtr(keyContent)

	response, err := client.UploadCertificate(request)
	if err != nil {
		return fmt.Errorf("上传证书失败: %v", err)
	}

	log.Printf("证书上传成功，证书ID: %s", *response.Response.CertificateId)
	return nil
}

// 重试配置
const (
	maxRetries = 3
	retryDelay = 5 * time.Second
)

// 带重试的上传证书到腾讯云
func uploadCertificateWithRetry(client *ssl.Client, certContent, keyContent string) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			log.Printf("第 %d 次重试上传证书...", i+1)
			time.Sleep(retryDelay)
		}

		err := uploadCertificate(client, certContent, keyContent)
		if err == nil {
			return nil
		}

		lastErr = err
		log.Printf("上传证书失败: %v", err)

		// 检查错误类型，某些错误可能不需要重试
		if sdkErr, ok := err.(*errors.TencentCloudSDKError); ok {
			// 如果是认证错误或参数错误，不需要重试
			if sdkErr.Code == "AuthFailure" || sdkErr.Code == "InvalidParameter" {
				return &CustomError{
					Op:      "uploadCertificateWithRetry",
					Err:     err,
					Message: "遇到不可重试的错误",
				}
			}
		}
	}

	return &CustomError{
		Op:      "uploadCertificateWithRetry",
		Err:     lastErr,
		Message: fmt.Sprintf("在 %d 次尝试后仍然失败", maxRetries),
	}
}

// 保存证书状态
func saveCertState(stateFile string, state *CertState) error {
	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(stateFile, data, 0644)
}

// 加载证书状态
func loadCertState(stateFile string) (*CertState, error) {
	var state CertState
	data, err := ioutil.ReadFile(stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &CertState{}, nil
		}
		return nil, err
	}

	err = yaml.Unmarshal(data, &state)
	if err != nil {
		return nil, err
	}

	return &state, nil
}

// 检查证书有效期
func checkCertificateValidity(certPath string, daysBeforeWarning int) error {
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		return &CustomError{
			Op:      "checkCertificateValidity",
			Err:     err,
			Message: "无法读取证书文件",
		}
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return &CustomError{
			Op:      "checkCertificateValidity",
			Message: "无法解析PEM格式证书",
		}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &CustomError{
			Op:      "checkCertificateValidity",
			Err:     err,
			Message: "无法解析X509证书",
		}
	}

	now := time.Now()
	if now.After(cert.NotAfter) {
		return &CustomError{
			Op:      "checkCertificateValidity",
			Message: fmt.Sprintf("证书已过期，过期时间：%v", cert.NotAfter),
		}
	}

	warningTime := cert.NotAfter.Add(-time.Duration(daysBeforeWarning) * 24 * time.Hour)
	if now.After(warningTime) {
		log.Printf("警告：证书将在 %v 后过期", cert.NotAfter.Sub(now).Round(24*time.Hour))
	}

	return nil
}

func main() {
	// 加载配置文件
	config, err := loadConfig("config.yaml")
	if err != nil {
		log.Printf("致命错误：无法加载配置文件: %v", err)
		os.Exit(1)
	}

	// 设置日志
	if config.Log.Enable {
		// 设置默认值
		if config.Log.MaxSize == 0 {
			config.Log.MaxSize = 10 // 默认10MB
		}
		if config.Log.MaxBackups == 0 {
			config.Log.MaxBackups = 5 // 默认保留5个备份
		}
		if config.Log.MaxAge == 0 {
			config.Log.MaxAge = 30 // 默认保留30天
		}

		writer := &lumberjack.Logger{
			Filename:   config.Log.Path,
			MaxSize:    config.Log.MaxSize, // MB
			MaxBackups: config.Log.MaxBackups,
			MaxAge:     config.Log.MaxAge, // days
			Compress:   config.Log.Compress,
		}
		log.SetOutput(writer)
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
		log.Printf("日志系统初始化完成，日志文件：%s", config.Log.Path)
	}

	// 加载证书状态
	stateFile := "cert_state.yaml"
	state, err := loadCertState(stateFile)
	if err != nil {
		log.Printf("致命错误：无法加载证书状态: %v", err)
		os.Exit(1)
	}

	// 检查证书有效期
	if err := checkCertificateValidity(config.CertPaths.FullChainPem, 30); err != nil {
		log.Printf("警告：证书有效期检查失败: %v", err)
		// 继续执行，因为这不是致命错误
	}

	// 计算当前证书的哈希值
	currentHash, err := calculateFileHash(config.CertPaths.FullChainPem)
	if err != nil {
		log.Printf("致命错误：无法计算证书哈希值: %v", err)
		os.Exit(1)
	}

	// 检查证书是否有更新
	if currentHash != state.Hash {
		log.Println("检测到证书更新，准备上传到腾讯云...")

		// 读取证书文件
		certContent, keyContent, err := loadCertificates(
			config.CertPaths.FullChainPem,
			config.CertPaths.PrivKeyPem,
		)
		if err != nil {
			log.Printf("致命错误：无法读取证书文件: %v", err)
			os.Exit(1)
		}

		// 初始化腾讯云客户端
		credential := common.NewCredential(config.SecretId, config.SecretKey)
		cpf := profile.NewClientProfile()
		if config.ValidateCertApi != "" {
			cpf.HttpProfile.Endpoint = config.ValidateCertApi
		}
		client, err := ssl.NewClient(credential, "", cpf)
		if err != nil {
			log.Printf("致命错误：无法初始化API客户端: %v", err)
			os.Exit(1)
		}

		// 上传证书（带重试）
		err = uploadCertificateWithRetry(client, certContent, keyContent)
		if err != nil {
			log.Printf("致命错误：上传证书失败: %v", err)
			os.Exit(1)
		}

		// 更新证书状态
		state.Hash = currentHash
		state.LastCheck = time.Now()
		if err := saveCertState(stateFile, state); err != nil {
			log.Printf("警告：无法保存证书状态: %v", err)
			// 继续执行，因为这不是致命错误
		}

		log.Println("证书更新完成")
	} else {
		log.Println("证书未发生变化，无需更新")
	}
}
