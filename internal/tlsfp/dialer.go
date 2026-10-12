// Package tlsfp 提供 TLS 指纹伪装（utls / JA3、JA4）。
// 移植自 sub2api 的 pkg/tlsfingerprint，Profile 数值与扩展顺序逐字保留：
// 目标指纹为 Node.js 24.x（JA3 44f88fca027f27bab4bb08d4af15f23e，
// JA4 t13d1714h1_5b57614c22b0_7baf387fc6ff），支持直连 / HTTP CONNECT / SOCKS5 三条路径。
package tlsfp

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

// Profile 描述 TLS 指纹配置；切片字段为空时使用内置默认值。
type Profile struct {
	Name                string
	CipherSuites        []uint16
	Curves              []uint16
	PointFormats        []uint16
	EnableGREASE        bool
	SignatureAlgorithms []uint16 // 为空使用 defaultSignatureAlgorithms
	ALPNProtocols       []string // 为空使用 ["http/1.1"]
	SupportedVersions   []uint16 // 为空使用 [TLS1.3, TLS1.2]
	KeyShareGroups      []uint16 // 为空使用 [X25519]
	PSKModes            []uint16 // 为空使用 [psk_dhe_ke]
	Extensions          []uint16 // 扩展类型 ID 顺序；为空使用 Node.js 24.x 默认顺序
}

// Dialer 直连场景的指纹 dialer。
type Dialer struct {
	profile          *Profile
	baseDialer       func(ctx context.Context, network, addr string) (net.Conn, error)
	handshakeTimeout time.Duration
}

// HTTPProxyDialer 通过 HTTP/HTTPS 代理 CONNECT 隧道建立指纹连接。
type HTTPProxyDialer struct {
	profile     *Profile
	proxyURL    *url.URL
	dialTimeout time.Duration
}

// SOCKS5ProxyDialer 通过 SOCKS5 代理建立指纹连接。
type SOCKS5ProxyDialer struct {
	profile     *Profile
	proxyURL    *url.URL
	dialTimeout time.Duration
}

var (
	defaultCipherSuites = []uint16{
		0x1301, 0x1302, 0x1303,
		0xc02b, 0xc02f, 0xc02c, 0xc030,
		0xcca9, 0xcca8,
		0xc009, 0xc013, 0xc00a, 0xc014,
		0x009c, 0x009d,
		0x002f, 0x0035,
	}

	defaultCurves = []utls.CurveID{
		utls.X25519,
		utls.CurveP256,
		utls.CurveP384,
	}

	defaultPointFormats = []uint16{0}

	defaultSignatureAlgorithms = []utls.SignatureScheme{
		0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
	}
)

// NewDialer 创建直连指纹 dialer；baseDialer 为 nil 时使用无超时 TCP 拨号（
// 调用方应传入带 DialTimeout 的拨号器，否则连接可能永久挂起）。
func NewDialer(profile *Profile, baseDialer func(ctx context.Context, network, addr string) (net.Conn, error), handshakeTimeout time.Duration) *Dialer {
	if baseDialer == nil {
		baseDialer = (&net.Dialer{}).DialContext
	}
	return &Dialer{profile: profile, baseDialer: baseDialer, handshakeTimeout: handshakeTimeout}
}

// NewHTTPProxyDialer 创建 HTTP/HTTPS 代理指纹 dialer。
func NewHTTPProxyDialer(profile *Profile, proxyURL *url.URL, dialTimeout time.Duration) *HTTPProxyDialer {
	return &HTTPProxyDialer{profile: profile, proxyURL: proxyURL, dialTimeout: dialTimeout}
}

// NewSOCKS5ProxyDialer 创建 SOCKS5 代理指纹 dialer。
func NewSOCKS5ProxyDialer(profile *Profile, proxyURL *url.URL, dialTimeout time.Duration) *SOCKS5ProxyDialer {
	return &SOCKS5ProxyDialer{profile: profile, proxyURL: proxyURL, dialTimeout: dialTimeout}
}

// DialTLSContext 通过 SOCKS5 隧道建立指纹连接：CONNECT → utls 握手。
func (d *SOCKS5ProxyDialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if d.proxyURL.User != nil {
		username := d.proxyURL.User.Username()
		password, _ := d.proxyURL.User.Password()
		auth = &proxy.Auth{User: username, Password: password}
	}

	proxyAddr := d.proxyURL.Host
	if d.proxyURL.Port() == "" {
		proxyAddr = net.JoinHostPort(d.proxyURL.Hostname(), "1080")
	}

	socksDialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, &net.Dialer{Timeout: d.dialTimeout})
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}

	conn, err := socksDialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 connect: %w", err)
	}

	return performTLSHandshake(ctx, conn, d.profile, addr, d.dialTimeout)
}

// DialTLSContext 通过 HTTP 代理 CONNECT 隧道建立指纹连接：
// TCP 连代理 → CONNECT → utls 握手。
func (d *HTTPProxyDialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var proxyAddr string
	if d.proxyURL.Port() != "" {
		proxyAddr = d.proxyURL.Host
	} else if d.proxyURL.Scheme == "https" {
		proxyAddr = net.JoinHostPort(d.proxyURL.Hostname(), "443")
	} else {
		proxyAddr = net.JoinHostPort(d.proxyURL.Hostname(), "80")
	}

	dialer := &net.Dialer{Timeout: d.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to proxy: %w", err)
	}

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if d.proxyURL.User != nil {
		username := d.proxyURL.User.Username()
		password, _ := d.proxyURL.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+auth)
	}

	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write CONNECT request: %w", err)
	}

	// CONNECT 响应读取受 dialTimeout 约束，避免代理接受连接后不响应时永久挂起。
	if d.dialTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(d.dialTimeout))
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	// CONNECT 响应无 body，不要关闭 resp.Body（它包裹的同一连接还要做 TLS 握手）。

	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	return performTLSHandshake(ctx, conn, d.profile, addr, d.dialTimeout)
}

// DialTLSContext 直连 + 指纹握手，用作 http.Transport.DialTLSContext。
func (d *Dialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.baseDialer(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return performTLSHandshake(ctx, conn, d.profile, addr, d.handshakeTimeout)
}

// performTLSHandshake 在已建立的 TCP/隧道连接上执行 utls 指纹握手；
// timeout > 0 时给握手叠加时间上限（TCP 建连之后的握手阶段也必须有界）。
func performTLSHandshake(ctx context.Context, conn net.Conn, profile *Profile, addr string, timeout time.Duration) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	spec := buildClientHelloSpecFromProfile(profile)
	tlsConn := utls.UClient(conn, &utls.Config{ServerName: host}, utls.HelloCustom)

	if err := tlsConn.ApplyPreset(spec); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("apply TLS preset: %w", err)
	}

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return tlsConn, nil
}

func toUTLSCurves(curves []uint16) []utls.CurveID {
	result := make([]utls.CurveID, len(curves))
	for i, c := range curves {
		result[i] = utls.CurveID(c)
	}
	return result
}

// defaultExtensionOrder 为 Node.js 24.x 的扩展顺序。
var defaultExtensionOrder = []uint16{
	0,     // server_name
	65037, // encrypted_client_hello
	23,    // extended_master_secret
	65281, // renegotiation_info
	10,    // supported_groups
	11,    // ec_point_formats
	35,    // session_ticket
	16,    // alpn
	5,     // status_request
	13,    // signature_algorithms
	18,    // signed_certificate_timestamp
	51,    // key_share
	45,    // psk_key_exchange_modes
	43,    // supported_versions
}

// isGREASEValue 判断是否符合 TLS GREASE 模式（0x?a?a）。
func isGREASEValue(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// buildClientHelloSpecFromProfile 依据 Profile 构建 ClientHelloSpec。
func buildClientHelloSpecFromProfile(profile *Profile) *utls.ClientHelloSpec {
	cipherSuites := defaultCipherSuites
	if profile != nil && len(profile.CipherSuites) > 0 {
		cipherSuites = profile.CipherSuites
	}

	curves := defaultCurves
	if profile != nil && len(profile.Curves) > 0 {
		curves = toUTLSCurves(profile.Curves)
	}

	pointFormats := defaultPointFormats
	if profile != nil && len(profile.PointFormats) > 0 {
		pointFormats = profile.PointFormats
	}

	signatureAlgorithms := defaultSignatureAlgorithms
	if profile != nil && len(profile.SignatureAlgorithms) > 0 {
		signatureAlgorithms = make([]utls.SignatureScheme, len(profile.SignatureAlgorithms))
		for i, s := range profile.SignatureAlgorithms {
			signatureAlgorithms[i] = utls.SignatureScheme(s)
		}
	}

	alpnProtocols := []string{"http/1.1"}
	if profile != nil && len(profile.ALPNProtocols) > 0 {
		alpnProtocols = profile.ALPNProtocols
	}

	supportedVersions := []uint16{utls.VersionTLS13, utls.VersionTLS12}
	if profile != nil && len(profile.SupportedVersions) > 0 {
		supportedVersions = profile.SupportedVersions
	}

	keyShareGroups := []utls.CurveID{utls.X25519}
	if profile != nil && len(profile.KeyShareGroups) > 0 {
		keyShareGroups = toUTLSCurves(profile.KeyShareGroups)
	}

	pskModes := []uint16{uint16(utls.PskModeDHE)}
	if profile != nil && len(profile.PSKModes) > 0 {
		pskModes = profile.PSKModes
	}

	enableGREASE := profile != nil && profile.EnableGREASE

	keyShares := make([]utls.KeyShare, len(keyShareGroups))
	for i, g := range keyShareGroups {
		keyShares[i] = utls.KeyShare{Group: g}
	}

	extOrder := defaultExtensionOrder
	if profile != nil && len(profile.Extensions) > 0 {
		extOrder = profile.Extensions
	}

	extensions := make([]utls.TLSExtension, 0, len(extOrder)+2)
	for _, id := range extOrder {
		if isGREASEValue(id) {
			extensions = append(extensions, &utls.UtlsGREASEExtension{})
			continue
		}
		switch id {
		case 0: // server_name
			extensions = append(extensions, &utls.SNIExtension{})
		case 5: // status_request (OCSP)
			extensions = append(extensions, &utls.StatusRequestExtension{})
		case 10: // supported_groups
			extensions = append(extensions, &utls.SupportedCurvesExtension{Curves: curves})
		case 11: // ec_point_formats
			extensions = append(extensions, &utls.SupportedPointsExtension{SupportedPoints: toUint8s(pointFormats)})
		case 13: // signature_algorithms
			extensions = append(extensions, &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: signatureAlgorithms})
		case 16: // alpn
			extensions = append(extensions, &utls.ALPNExtension{AlpnProtocols: alpnProtocols})
		case 18: // signed_certificate_timestamp
			extensions = append(extensions, &utls.SCTExtension{})
		case 23: // extended_master_secret
			extensions = append(extensions, &utls.ExtendedMasterSecretExtension{})
		case 35: // session_ticket
			extensions = append(extensions, &utls.SessionTicketExtension{})
		case 43: // supported_versions
			extensions = append(extensions, &utls.SupportedVersionsExtension{Versions: supportedVersions})
		case 45: // psk_key_exchange_modes
			extensions = append(extensions, &utls.PSKKeyExchangeModesExtension{Modes: toUint8s(pskModes)})
		case 50: // signature_algorithms_cert
			extensions = append(extensions, &utls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: signatureAlgorithms})
		case 51: // key_share
			extensions = append(extensions, &utls.KeyShareExtension{KeyShares: keyShares})
		case 0xfe0d: // encrypted_client_hello (ECH, 65037)
			// 发送 GREASE ECH（随机载荷），模拟 Node.js 无真实 ECHConfig 时的行为；
			// 空 GenericExtension 会被校验 ECH 格式的服务器拒绝。
			extensions = append(extensions, &utls.GREASEEncryptedClientHelloExtension{})
		case 0xff01: // renegotiation_info
			extensions = append(extensions, &utls.RenegotiationInfoExtension{})
		default:
			extensions = append(extensions, &utls.GenericExtension{Id: id})
		}
	}

	if enableGREASE && (profile == nil || len(profile.Extensions) == 0) {
		extensions = append([]utls.TLSExtension{&utls.UtlsGREASEExtension{}}, extensions...)
		extensions = append(extensions, &utls.UtlsGREASEExtension{})
	}

	return &utls.ClientHelloSpec{
		CipherSuites:       cipherSuites,
		CompressionMethods: []uint8{0},
		Extensions:         extensions,
		TLSVersMax:         utls.VersionTLS13,
		TLSVersMin:         utls.VersionTLS10,
	}
}

func toUint8s(vals []uint16) []uint8 {
	out := make([]uint8, len(vals))
	for i, v := range vals {
		out[i] = uint8(v)
	}
	return out
}
