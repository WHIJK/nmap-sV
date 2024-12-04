/*
 * @Author: OvO
 * @Date: 2024-12-04 12:19:47
 * @LastEditors: Please set LastEditors
 * @LastEditTime: 2024-12-04 18:21:10
 * @Description: Description
 */
package script

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func detectJDWP(address string) (string, string, string, error) {
	// Connect to the target
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return "", "", "", err
	}
	defer conn.Close()

	// JDWP Handshake request in hexadecimal
	handshake := []byte{
		0x4a, 0x44, 0x57, 0x50, 0x2d, 0x48, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61, 0x6b, 0x65,
		0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01,
	}
	_, err = conn.Write(handshake)
	if err != nil {
		return "", "", "", err
	}

	// Read the response (expecting at least 18 bytes)
	response := make([]byte, 2048)
	totalBytesRead := 0

	// Loop to accumulate the data, read until you have enough bytes
	for totalBytesRead < 18 {
		n, err := conn.Read(response[totalBytesRead:])
		if err != nil && err != io.EOF {
			return "", "", "", err
		}
		totalBytesRead += n

		if err == io.EOF {
			break
		}
	}

	// We expect at least 18 bytes in the response
	if totalBytesRead < 18 {
		// Incomplete response, possibly a non-JDWP service
		return "", "", "", fmt.Errorf("received insufficient data for JDWP handshake")
	}

	// Check the handshake response and extract relevant information
	respStr := string(response[:totalBytesRead])
	match := parseJDWPResponse(respStr)
	if match == nil {
		// No version info found, return unknown
		return "", "", "", fmt.Errorf("no version info found")
	}

	// Extract version details from the match
	return match[0], match[2], match[1], nil
}

// Parses the JDWP handshake response for version information
func parseJDWPResponse(response string) []string {
	// Look for the JDWP version details in the handshake response
	if strings.HasPrefix(response, "JDWP-Handshake") {
		parts := strings.Split(response, "\n")
		if len(parts) >= 3 {
			// Return product, extra info, version
			return []string{parts[0], parts[1], parts[2]}
		}
	}
	return nil
}

func JdwpDetectVersion(address string) string {
	_, version, _, err := detectJDWP(address)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return ""
	}
	return version
}

type JDWPScript struct{}

func (jdwp *JDWPScript) RunScripts(address string) string {
	// JDWP的处理逻辑
	return JdwpDetectVersion(address)
}
