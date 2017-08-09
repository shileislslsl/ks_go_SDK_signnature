package ksSdk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/olizax/web"
	"io"
	"io/ioutil"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	JS_ACCESS_KEY  = "your key"
	JS_SECRET_KEY  = "your secret"
	JS_HOST        = "ksvs.cn-beijing-6.api.ksyun.com"
	JS_REGION      = "cn-beijing-6"
	JS_SERVICE     = "ksvs"
	JS_SIGN_HEADER = "host;x-amz-date"
	JS_ALGOR       = "AWS4-HMAC-SHA256"
	JS_URL_PRO     = "https://ksvs.cn-beijing-6.api.ksyun.com?Action=KSDKAuth&Version=2017-04-01&Pkg="
)

type Interface interface {
	Len() int
	Less(i, j int) bool
	Swap(i, j int)
}
type strslice []string

func (s strslice) Len() int           { return len(s) }
func (s strslice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s strslice) Less(i, j int) bool { return s[i] < s[j] }

func sign(key []byte, msg string) []byte {
	msgs := []byte(msg)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msgs))
	has_str := mac.Sum(nil)
	return has_str
}

func getSignatureKey(key, dateStamp, regionName, serviceName string) []byte {
	key = "AWS4" + key
	keys := []byte(key)
	kDate := sign(keys, dateStamp)
	kRegion := sign(kDate, regionName)
	kService := sign(kRegion, serviceName)
	kSigning := sign(kService, "aws4_request")
	return kSigning
}

func getCanonicalQueryStringUrl(tar_url string) (string, error) {
	u, err := url.Parse(tar_url)
	if err != nil {
		utils.Error("parse url error :", err)
		return "", err
	}
	parmter := u.RawQuery
	parmterlist := strings.Split(parmter, "&")
	sort.Sort(strslice(parmterlist))
	b := bytes.Buffer{}
	for i, j := range parmterlist {
		b.WriteString(j)
		c := len(parmterlist) - 1
		if i != c {
			b.WriteString("&")
		}
	}
	s := b.String()
	return s, err
}

func GetAuth(ctx *web.Context) string {
	param, _ := ioutil.ReadAll(ctx.Request.Body)
	args := make(map[string]string)
	if err_json := json.Unmarshal(param, &args); err_json != nil {
		return "err"
	}

	app := args["pkg"]
	if app == "" {
		return "err"
	}

	tar_url := Settings.JS_URL_PRO + app

	loacat_date := time.Now()
	utc_time := loacat_date.UTC()
	amzdate := utc_time.Format("20060102T150405Z")
	datestamp := utc_time.Format("20060102")
	canonical_querystring, err := getCanonicalQueryStringUrl(tar_url)
	if err != nil {
		return "err"
	}

	canonical_headers := "host:" + JS_HOST + "\n" + "x-amz-date:" + amzdate + "\n"

	h := sha256.New()
	var body string
	io.WriteString(h, body)
	payload_hash := hex.EncodeToString(h.Sum(nil))

	canonical_request := "GET" + "\n" + "/" + "\n" + canonical_querystring + "\n" + canonical_headers + "\n" + JS_SIGN_HEADER + "\n" + payload_hash

	h_new := sha256.New()
	io.WriteString(h_new, canonical_request)
	request_str_sha := hex.EncodeToString(h_new.Sum(nil))

	scope_str := datestamp + "/" + Settings.JS_REGION + "/" + JS_SERVICE + "/" + "aws4_request"

	string_to_sign := JS_ALGOR + "\n" + amzdate + "\n" + scope_str + "\n" + request_str_sha

	signing_key := getSignatureKey(JS_SECRET_KEY, datestamp, JS_REGION, JS_SERVICE)
	signature_byte := sign(signing_key, string_to_sign)
	signature := hex.EncodeToString(signature_byte)

	authorization_header := JS_ALGOR + " " + "Credential=" + JS_ACCESS_KEY + "/" + scope_str + ", " + "SignedHeaders=" + JS_SIGN_HEADER + ", " + "Signature=" + signature
	//返回格式自己处理下
	return "authorization_header:" + authorization_header + "x-amz-date:" + amzdate
}
