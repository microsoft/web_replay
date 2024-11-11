// Modifications Copyright (c) Microsoft Corporation.
// Licensed under the BSD-3-Clause license.
//
// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package webreplay

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"time"
)

const errStatus = http.StatusInternalServerError

func makeLogger(req *http.Request, quietMode bool) func(msg string, args ...interface{}) {
	if quietMode {
		return func(string, ...interface{}) {}
	}
	prefix := fmt.Sprintf("ServeHTTP(%s): ", req.URL)
	return func(msg string, args ...interface{}) {
		log.Print(prefix + fmt.Sprintf(msg, args...))
	}
}

// fixupRequestURL adds a scheme and host to req.URL.
// Adding the scheme is necessary since RoundTrip doesn't like an empty scheme.
// Adding the host is optional, but makes req.URL print more nicely.
func fixupRequestURL(req *http.Request, scheme string) {
	req.URL.Scheme = scheme
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
}

// updateDate is the basic function for date adjustment.
func updateDate(h http.Header, name string, now, oldNow time.Time) {
	val := h.Get(name)
	if val == "" {
		return
	}
	oldTime, err := http.ParseTime(val)
	if err != nil {
		return
	}
	newTime := now.Add(oldTime.Sub(oldNow))
	h.Set(name, newTime.UTC().Format(http.TimeFormat))
}

// updateDates updates "Date" header as current time and adjusts "Last-Modified"/"Expires" against it.
func updateDates(h http.Header, now time.Time) {
	oldNow, err := http.ParseTime(h.Get("Date"))
	h.Set("Date", now.UTC().Format(http.TimeFormat))
	if err != nil {
		return
	}
	updateDate(h, "Last-Modified", now, oldNow)
	updateDate(h, "Expires", now, oldNow)
}

// NewReplayingProxy constructs an HTTP proxy that replays responses from an archive.
// The proxy is listening for requests on a port that uses the given scheme (e.g., http, https).
func NewReplayingProxy(ma *MultipleArchive, scheme string, quietMode bool,
	excludesList string, disableReqDelay bool, siteLog *SiteLog) http.Handler {
	transport := http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &replayingProxy{
		transport,
		ma,
		scheme,
		quietMode,
		strings.Split(excludesList, " "),
		disableReqDelay,
		siteLog,
	}
}

type replayingProxy struct {
	tr              *http.Transport
	ma              *MultipleArchive
	scheme          string
	quietMode       bool
	excludesList    []string
	disableReqDelay bool
	siteLog         *SiteLog
}

func (proxy *replayingProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/web-page-replay-generate-200" {
		w.WriteHeader(200)
		return
	}

	if req.URL.Path == "/web-page-replay-record-log" {
		log.Printf("Received /web-page-replay-record-log")
		proxy.siteLog.recordLog(req)
		return
	}

	if req.URL.Path == "/web-page-replay-save-log" {
		log.Printf("Saving site log")
		proxy.siteLog.saveLog()
		return
	}

	if req.URL.Path == "/web-page-replay-command-exit" {
		log.Printf("Shutting down. Received /web-page-replay-command-exit")
		os.Exit(0)
		return
	}

	if req.URL.Path == "/web-page-replay-reset-replay-chronology" {
		log.Printf("Received /web-page-replay-reset-replay-chronology")
		log.Printf("Reset replay order to start.")
		proxy.ma.CurrentArchive().StartNewReplaySession()
		return
	}

	if req.URL.Path == "/web-page-replay-change-archive" {
		n := req.URL.Query().Get("n")
		log.Printf("Received /web-page-replay-change-archive with n=%v", n)

		w.Write([]byte("done"))
		proxy.ma.ChangeArchive(n)

		return
	}

	fixupRequestURL(req, proxy.scheme)
	logf := makeLogger(req, proxy.quietMode)

	if ExcludeRequest(req, proxy.excludesList) {
		if req.ContentLength == 0 {
			req.Body = nil
		}

		// Make the external request.
		// If RoundTrip fails, convert the response to a 500.
		resp, err := proxy.tr.RoundTrip(req)
		if err != nil {
			logf("RoundTrip failed: %v", err)
			resp = &http.Response{
				Status:     http.StatusText(errStatus),
				StatusCode: errStatus,
				Proto:      req.Proto,
				ProtoMajor: req.ProtoMajor,
				ProtoMinor: req.ProtoMinor,
				Body:       ioutil.NopCloser(bytes.NewReader(nil)),
			}
		}

		// Transform.
		for _, t := range proxy.ma.CurrentTransformers() {
			t.Transform(req, resp)
		}

		responseBodyAfterTransform, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logf("warning: transformed response truncated: %v", err)
		}

		// Forward the response.
		logf("serving %d, %d bytes (EXCLUDE)", resp.StatusCode, len(responseBodyAfterTransform))
		for k, v := range resp.Header {
			w.Header()[k] = append([]string{}, v...)
		}
		w.WriteHeader(resp.StatusCode)
		if n, err := io.Copy(w, bytes.NewReader(responseBodyAfterTransform)); err != nil {
			logf("warning: client response truncated (%d/%d bytes): %v", n, len(responseBodyAfterTransform), err)
		}

		return
	}

	// Lookup the response in the archive.

	t0 := time.Now()
	_, storedResp, dur, err := proxy.ma.CurrentArchive().FindRequest(req)
	t1 := time.Now()

	if err != nil {
		_, storedResp, dur, err = proxy.ma.InitArchive().FindRequest(req)
		t1 = time.Now()
	}

	if err != nil {
		logf("couldn't find matching request: %v", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	defer storedResp.Body.Close()

	if !proxy.disableReqDelay {
		// Delay for the HTTP roundtrip duration
		time.Sleep(dur - t1.Sub(t0))
	}

	// Check if the stored Content-Encoding matches an encoding allowed by the client.
	// If not, transform the response body to match the client's Accept-Encoding.
	clientAE := strings.ToLower(req.Header.Get("Accept-Encoding"))
	originCE := strings.ToLower(storedResp.Header.Get("Content-Encoding"))
	if !strings.Contains(clientAE, originCE) {
		logf("translating Content-Encoding [%s] -> [%s]", originCE, clientAE)
		body, err := ioutil.ReadAll(storedResp.Body)
		if err != nil {
			logf("error reading response body from archive: %v", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, err = decompressBody(originCE, body)
		if err != nil {
			logf("error decompressing response body: %v", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, ce, err := CompressBody(clientAE, body)
		if err != nil {
			logf("error recompressing response body: %v", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		storedResp.Header.Set("Content-Encoding", ce)
		storedResp.Body = ioutil.NopCloser(bytes.NewReader(body))
		// ContentLength has changed, so update the outgoing headers accordingly.
		if storedResp.ContentLength >= 0 {
			storedResp.ContentLength = int64(len(body))
			storedResp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		}
	}

	// Update dates in response header.
	updateDates(storedResp.Header, time.Now())

	// Transform.
	for _, t := range proxy.ma.CurrentTransformers() {
		t.Transform(req, storedResp)
	}

	if req.URL.Path != storedResp.Request.URL.Path {
		logf(
			"serving %v response (NON-EXACT PATH MATCH; resp path = %s)",
			storedResp.StatusCode,
			storedResp.Request.URL.Path,
		)
	} else if req.URL.String() != storedResp.Request.URL.String() {
		logf(
			"serving %v response (NON-EXACT QUERY MATCH; resp query = %s)",
			storedResp.StatusCode,
			storedResp.Request.URL.RawQuery,
		)
	} else {
		logf("serving %v response", storedResp.StatusCode)
	}

	// Forward the response.
	for k, v := range storedResp.Header {
		w.Header()[k] = append([]string{}, v...)
	}
	w.WriteHeader(storedResp.StatusCode)
	if _, err := io.Copy(w, storedResp.Body); err != nil {
		logf("warning: client response truncated: %v", err)
	}
}

// NewRecordingProxy constructs an HTTP proxy that records responses into an archive.
// The proxy is listening for requests on a port that uses the given scheme (e.g., http, https).
func NewRecordingProxy(mwa *MultipleWritableArchive, scheme string, siteLog *SiteLog) http.Handler {
	transport := http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	return &recordingProxy{
		transport,
		mwa,
		scheme,
		siteLog,
	}
}

type recordingProxy struct {
	tr      *http.Transport
	mwa     *MultipleWritableArchive
	scheme  string
	siteLog *SiteLog
}

func (proxy *recordingProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/web-page-replay-generate-200" {
		w.WriteHeader(200)
		return
	}

	if req.URL.Path == "/web-page-replay-record-log" {
		log.Printf("Received /web-page-replay-record-log")
		proxy.siteLog.recordLog(req)
		return
	}

	if req.URL.Path == "/web-page-replay-save-log" {
		log.Printf("Saving site log")
		proxy.siteLog.saveLog()
		return
	}

	if req.URL.Path == "/web-page-replay-command-exit" {
		proxy.recordExtraURLs()

		log.Printf("Shutting down. Received /web-page-replay-command-exit")
		if err := proxy.mwa.Close(); err != nil {
			log.Printf("Error flushing archive: %v", err)
		}
		os.Exit(0)
		return
	}

	if req.URL.Path == "/web-page-replay-change-archive" {
		n := req.URL.Query().Get("n")
		log.Printf("Received /web-page-replay-change-archive with n=%v", n)

		w.Write([]byte("done"))
		proxy.mwa.ChangeArchive(n)

		return
	}

	fixupRequestURL(req, proxy.scheme)
	logf := makeLogger(req, false)
	// https://github.com/golang/go/issues/16036. Server requests always
	// have non-nil body even for GET and HEAD. This prevents http.Transport
	// from retrying requests on dead reused conns.
	if req.ContentLength == 0 {
		req.Body = nil
	}

	// Read the entire request body (for POST) before forwarding to the server
	// so we can save the entire request in the archive.
	var requestBody []byte
	if req.Body != nil {
		var err error
		requestBody, err = ioutil.ReadAll(req.Body)
		if err != nil {
			logf("read request body failed: %v", err)
			w.WriteHeader(errStatus)
			return
		}
		req.Body = ioutil.NopCloser(bytes.NewReader(requestBody))
	}

	// Make the external request.
	// If RoundTrip fails, convert the response to a 500.
	t0 := time.Now()
	resp, err := proxy.tr.RoundTrip(req)
	t1 := time.Now()

	if err != nil {
		logf("RoundTrip failed: %v", err)
		resp = &http.Response{
			Status:     http.StatusText(errStatus),
			StatusCode: errStatus,
			Proto:      req.Proto,
			ProtoMajor: req.ProtoMajor,
			ProtoMinor: req.ProtoMinor,
			Body:       ioutil.NopCloser(bytes.NewReader(nil)),
		}
	}

	// Copy the entire response body.
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logf("warning: origin response truncated: %v", err)
	}
	resp.Body.Close()

	// Restore req body (which was consumed by RoundTrip) and record original response without transformation.
	resp.Body = ioutil.NopCloser(bytes.NewReader(responseBody))
	if req.Body != nil {
		req.Body = ioutil.NopCloser(bytes.NewReader(requestBody))
	}
	if err := proxy.mwa.CurrentArchive().RecordRequest(req, resp, t1.Sub(t0)); err != nil {
		logf("failed recording request: %v", err)
	}

	// Restore req and response body which are consumed by RecordRequest.
	if req.Body != nil {
		req.Body = ioutil.NopCloser(bytes.NewReader(requestBody))
	}
	resp.Body = ioutil.NopCloser(bytes.NewReader(responseBody))

	// Transform.
	for _, t := range proxy.mwa.CurrentTransformers() {
		t.Transform(req, resp)
	}

	responseBodyAfterTransform, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logf("warning: transformed response truncated: %v", err)
	}

	// Forward the response.
	logf("serving %d, %d bytes", resp.StatusCode, len(responseBodyAfterTransform))
	for k, v := range resp.Header {
		w.Header()[k] = append([]string{}, v...)
	}
	w.WriteHeader(resp.StatusCode)
	if n, err := io.Copy(w, bytes.NewReader(responseBodyAfterTransform)); err != nil {
		logf("warning: client response truncated (%d/%d bytes): %v", n, len(responseBodyAfterTransform), err)
	}
}

func (proxy *recordingProxy) recordExtraURLs() {
	files, err := os.ReadDir(".\\extra_urls")

	if err != nil {
		return
	}

	log.Println("Handling provided extra URLs")

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		f, err := os.Open(
			fmt.Sprintf(".\\extra_urls\\%s", file.Name()),
		)

		if err != nil {
			log.Printf("Error reading file %s", file.Name())
			continue
		}

		defer f.Close()

		scanner := bufio.NewScanner(f)

		for scanner.Scan() {
			urlStr := scanner.Text()

			if err != nil {
				continue
			}

			method := "GET"

			if strings.Contains(file.Name(), "_POST") {
				method = "POST"
			}

			reqTemplate, err := http.NewRequest(method, urlStr, nil)

			if err != nil {
				continue
			}

			proxy.ServeHTTP(httptest.NewRecorder(), reqTemplate)
		}

		if err := scanner.Err(); err != nil {
			log.Printf("Error reading line %s", file.Name())
		}
	}
}
