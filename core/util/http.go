package util

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

/*
@Author: OvO
@Date: 2023/11/17 13:48
*/

func GetHttpBanner(url string, timeout int) (status bool, html string) {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: time.Duration(timeout) * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	dump, _ := httputil.DumpResponse(resp, true)
	if err != nil {
		return false, ""
	}
	return true, string(dump)
}
