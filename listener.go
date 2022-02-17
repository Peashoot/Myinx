package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// 类Nginx 实现：正则匹配转发,IP过滤,配置同步更新,超时处理,记录源IP,支持HTTPS

// Conf 配置类
type Conf struct {
	ForwardTimeout    int    `json:"forward_time_out"`    // 最大转发超时时间
	EnableRealIP      bool   `json:"enable_real_ip"`      // 请求头添加请求方IP
	EnableForwardPath bool   `json:"enable_forward_path"` // 请求头添加转发路径
	AnonUpdate        bool   `json:"anon_update"`         // 路由配置修改后立刻更新
	ListenPort        int    `json:"listen_port"`         // 监听端口
	UseHTTPSMode      bool   `json:"use_https_mode"`      // 使用https
	CertificateFile   string `json:"cert_file_path"`      // 证书文件路径
	CertKeyFile       string `json:"cert_key_file_path"`  // 证书密钥文件路径
	ForbidListPath    string `json:"forbid_list_path"`    // IP黑名单列表文件路径
	WhiteListPath     string `json:"white_list_path"`     // IP白名单列表文件路径
	RouteRules        []Rule `json:"route_rules"`         // 转发规则
}

// Rule 转发规则
type Rule struct {
	Location     string   `json:"location"`          // 路由URL匹配规则
	LocationPath string   `json:"location ~"`        // 路由路径匹配规则
	ProxyPass    string   `json:"proxy_pass"`        // 路由转发规则
	MSMode       bool     `json:"master_salve_mode"` // 主从备份模式
	SalvePasses  []string `json:"salve_passes"`      // 从属转发地址（顺序优先级）
}

var (
	routeMap   map[*regexp.Regexp]Rule // 转发路由
	routeConf  Conf                    // 路由配置
	reqLimit   bool                    // 限制请求模式（白名单启用）
	forbidList []string                // 黑名单列表
	whiteList  []string                // 白名单列表
)

func init() {
	// 获取配置
	routeConf.GetConf()
	routeMap = make(map[*regexp.Regexp]Rule)
	// 创建路由字典
	routeConf.GearRoute()
}

func main() {
	watch, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Watcher load failure")
	}
	defer watch.Close()
	err = watch.Add("config.json")
	go WatcherRunEvent(watch)
	if whiteList, err = GetWhiteList(); err == nil && len(whiteList) > 0 {
		reqLimit = true
	}
	forbidList, err = GetForbidList()
	server := http.NewServeMux()
	server.HandleFunc("/", Redirect)
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites:             []uint16{tls.TLS_RSA_WITH_AES_256_CBC_SHA, tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
	}
	srv := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", routeConf.ListenPort),
		Handler:      server,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	if routeConf.UseHTTPSMode {
		srv.ListenAndServeTLS(routeConf.CertificateFile, routeConf.CertKeyFile)
	} else {
		srv.ListenAndServe()
	}
}

// GetConf 获取配置
func (c *Conf) GetConf() *Conf {
	confBytes, err := ioutil.ReadFile("config.json")
	log.Printf("config file info: " + string(confBytes))
	if err != nil {
		log.Printf("Config file read failure.%v ", err)
	}
	err = json.Unmarshal(confBytes, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	return c
}

// GearRoute 添加路由规则字典
func (c *Conf) GearRoute() {
	for _, rule := range c.RouteRules {
		var location string
		if rule.LocationPath != "" {
			location = rule.LocationPath
		} else if rule.Location != "" {
			location = rule.Location
		}
		routeReg, err := regexp.Compile(location)
		if err != nil {
			log.Fatalln(err)
		}
		routeMap[routeReg] = rule
	}
}

// Router 根据原请求地址和路由规则获取应该转发的地址
// 参数说明：  原请求地址         正则路由表达式         正则路由规则|目标请求地址|是否匹配路由
func Router(reqURL *url.URL, regRoute *regexp.Regexp, recvRule Rule) (string, bool) {
	strReqURL := reqURL.String()
	if recvRule.LocationPath != "" {
		strReqURL = reqURL.Path
	}
	if !regRoute.Match([]byte(strReqURL)) {
		return strReqURL, false
	}
	var newReqURL = recvRule.ProxyPass
	groups := regRoute.FindStringSubmatch(strReqURL)
	for i := len(groups) - 1; i >= 0; i-- {
		newReqURL = strings.Replace(newReqURL, fmt.Sprintf("$%d", i), groups[i], -1)
	}
	return newReqURL, true
}

// Redirect 将http请求地址进行转换
// 参数说明：        原http请求        重定向的http请求
func Redirect(w http.ResponseWriter, req *http.Request) {
	if Intercept(req, w) {
		return
	}
	newReqURL := GetRealReqURL(req)
	newReq, errMsg := GetRealReq(req, newReqURL)
	if errMsg != "" {
		io.WriteString(w, errMsg)
		return
	}
	header, body, errMsg := GetRealResBodyAndHeader(newReq)
	if errMsg != "" {
		io.WriteString(w, errMsg)
		return
	}
	SetProxyResBodyAndHeader(w, header, body)
}

// GetRealReqURL 获取实际请求的URL
// 参数说明：       代理获取到的请求URL|实际请求的URL
func GetRealReqURL(req *http.Request) string {
	var newReqURL = req.URL.String()
	var changed bool
	for regRoute, recvRule := range routeMap {
		if newReqURL, changed = Router(req.URL, regRoute, recvRule); changed {
			break
		}
	}
	return newReqURL
}

// GetRealReq 获取实际的请求
// 参数说明：   代理获取到的请求URL    实际请求的URL       实际的请求    错误信息
func GetRealReq(req *http.Request, newReqURL string) (*http.Request, string) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return req, "400: Bad Request"
	}
	newReq, err := http.NewRequest(req.Method, newReqURL, strings.NewReader(string(body)))
	if err != nil {
		return req, "400: Bad Request"
	}
	for k, v := range req.Header {
		newReq.Header.Set(k, strings.Join(v, ","))
	}
	if routeConf.EnableRealIP {
		newReq.Header.Set("X-Real-IP", req.RemoteAddr)
	}
	if routeConf.EnableForwardPath {
		var proxyAddXForwardedFor []string
		if proxyAddXForwardedFor, ok := newReq.Header["X-Forwarded-For"]; !ok {
			proxyAddXForwardedFor = []string{req.RemoteAddr}
		} else {
			proxyAddXForwardedFor = append(proxyAddXForwardedFor, req.RemoteAddr)
		}
		newReq.Header.Set("X-Forwarded-For", strings.Join(proxyAddXForwardedFor, ","))
	}
	return newReq, ""
}

// GetRealResBodyAndHeader 获取实际响应的body和响应头
// 参数说明：                    实际的http请求        响应body    响应头  错误信息
func GetRealResBodyAndHeader(newReq *http.Request) (http.Header, []byte, string) {
	http.DefaultClient.Timeout = time.Duration(routeConf.ForwardTimeout) * time.Millisecond
	res, err := http.DefaultClient.Do(newReq)
	if err != nil {
		return nil, nil, "404: Not Found"
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, nil, "400: Bad Request"
	}
	return res.Header, body, ""
}

// SetProxyResBodyAndHeader 设置代理响应的body和响应头
// 参数说明：                       代理响应操作类         实际的响应头    实际的响应body
func SetProxyResBodyAndHeader(w http.ResponseWriter, header http.Header, body []byte) {
	// set response header
	for k, v := range header {
		w.Header().Set(k, v[0])
	}
	io.WriteString(w, string(body))
}

// WatcherRunEvent 文件监视器运行方法
// 参数说明：	           文件监视器
func WatcherRunEvent(watch *fsnotify.Watcher) {
	for {
		select {
		case ev := <-watch.Events:
			{
				if ev.Op&fsnotify.Write == fsnotify.Write {
					var tempConf Conf
					tempConf.GetConf()
					if tempConf.AnonUpdate {
						routeConf = tempConf
						routeConf.GearRoute()
					}
				} else {
					log.Println("Config file changed with abnormal operation")
				}
			}
		case <-watch.Errors:
			{
				log.Println("Watcher run with error")
			}
		}
	}
}

// GetForbidList 获取黑名单过滤IP列表
// 参数说明：             黑名单IP列表         错误
func GetForbidList() (forbidList []string, err error) {
	if reqLimit {
		return
	}
	if bytes, err := ioutil.ReadFile(routeConf.ForbidListPath); err == nil {
		txtInfo := string(bytes)
		forbidList = strings.Split(txtInfo, "\r\n")
	}
	return
}

// GetWhiteList 获取白名单过滤IP列表
// 参数说明：            白名单IP列表        错误
func GetWhiteList() (whiteList []string, err error) {
	if bytes, err := ioutil.ReadFile(routeConf.WhiteListPath); err == nil {
		txtInfo := string(bytes)
		whiteList = strings.Split(txtInfo, "\r\n")
	}
	return
}

// Intercept 判断该请求是否符合IP过滤规则
// 参数说明：       请求内容             代理响应操作类       是否拒绝请求
func Intercept(req *http.Request, w http.ResponseWriter) (refused bool) {
	if reqLimit {
		for _, whiteIP := range whiteList {
			if whiteIP == "" {
				continue
			}
			whiteReg, err := regexp.Compile(whiteIP)
			if err == nil && whiteReg.MatchString(req.RemoteAddr) {
				refused = false
				return
			}
		}
		refused = true
		io.WriteString(w, "403：Forbidden")
	} else {
		for _, forbidIP := range forbidList {
			if forbidIP == "" {
				continue
			}
			forbidReg, err := regexp.Compile(forbidIP)
			if err == nil && forbidReg.MatchString(req.RemoteAddr) {
				refused = true
				io.WriteString(w, "403：Forbidden")
				return
			}
		}
		refused = false
	}
	return
}
