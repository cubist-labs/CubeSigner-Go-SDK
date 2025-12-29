// Package utils provides various utilities for the SDK.
package utils

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

// RetryOn5XX will retry the request up to 3 times, with 100ms, 200ms, and 400ms delays.
// After exhausting the tries, or on success, the http response is returned as is.
func RetryOn5XX(httpClient *http.Client, request *http.Request) (*http.Response, error) {
	delaysMs := []int64{100, 200, 400}
	var resp *http.Response
	var err error

	for _, delayMs := range delaysMs {
		// Execute the request, retry if 5XX response
		resp, err = httpClient.Do(request)
		if err != nil {
			return nil, err
		}
		// Read status and exit if not 500
		if !strings.HasPrefix(resp.Status, "5") {
			break
		}

		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}

	return resp, nil
}

// GetHttpClient returns a pre-configured http client.
// This helps ensure the configuration remains the same.
func GetHttpClient() *http.Client {
	timeout, _ := time.ParseDuration("1m")
	return &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
			MaxIdleConns:        32,
			MaxConnsPerHost:     32,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     600 * time.Second,
		},
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       timeout,
	}
}

// GetDefaultSessionFilePath returns the default path
// for CubeSigner session file
func GetDefaultSessionFilePath() (string, error) {
	userHome, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch os := runtime.GOOS; os {
	case "darwin":
		return fmt.Sprintf("%s/Library/Application Support/cubesigner/management-session.json", userHome), nil
	case "linux":
		return fmt.Sprintf("%s/.config/cubesigner/management-session.json", userHome), nil
	default:
		return "", errors.New("unsupported OS")
	}
}
