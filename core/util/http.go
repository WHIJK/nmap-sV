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
	// Set your custom User-Agent here
	userAgent := "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36"

	// Set up the transport with the necessary timeout and TLS config
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: time.Duration(timeout) * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Disable TLS verification
		},
	}

	// Create a custom HTTP client with the transport
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	// Create a new request to set the User-Agent header
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, ""
	}

	// Set the User-Agent header
	req.Header.Set("User-Agent", userAgent)

	// Send the request and get the response
	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	// Dump the response including headers and body
	dump, _ := httputil.DumpResponse(resp, true)
	if err != nil {
		return false, ""
	}
	return true, string(dump)
}
