// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package webreplay

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	easyjson "github.com/mailru/easyjson"
)

var ErrNotFound = errors.New("not found")

// ArchivedRequest contains a single request and its response.
// Immutable after creation.
type ArchivedRequest struct {
	SerializedRequest   []byte
	SerializedResponse  []byte // if empty, the request failed
	LastServedSessionId uint32
	Duration            time.Duration
}

// RequestMatch represents a match when querying the archive for responses to a request
type RequestMatch struct {
	Match      *ArchivedRequest
	Request    *http.Request
	Response   *http.Response
	MatchRatio float64
}

func (requestMatch *RequestMatch) SetMatch(
	match *ArchivedRequest,
	request *http.Request,
	response *http.Response,
	ratio float64) {
	requestMatch.Match = match
	requestMatch.Request = request
	requestMatch.Response = response
	requestMatch.MatchRatio = ratio
}

func serializeRequest(req *http.Request, resp *http.Response, dur time.Duration) (*ArchivedRequest, error) {
	ar := &ArchivedRequest{}
	{
		var buf bytes.Buffer
		if err := req.Write(&buf); err != nil {
			return nil, fmt.Errorf("failed writing request for %s: %v", req.URL.String(), err)
		}
		ar.SerializedRequest = buf.Bytes()
	}
	{
		var buf bytes.Buffer
		if err := resp.Write(&buf); err != nil {
			return nil, fmt.Errorf("failed writing response for %s: %v", req.URL.String(), err)
		}
		ar.SerializedResponse = buf.Bytes()
	}

	// Set request roundtrip duration
	ar.Duration = dur

	return ar, nil
}

func (ar *ArchivedRequest) unmarshal(scheme string) (*http.Request, *http.Response, error) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(ar.SerializedRequest)))
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't unmarshal request: %v", err)
	}

	if req.URL.Host == "" {
		req.URL.Host = req.Host
		req.URL.Scheme = scheme
	}

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(ar.SerializedResponse)), req)
	if err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, nil, fmt.Errorf("couldn't unmarshal response: %v", err)
	}
	return req, resp, nil
}

// Archive contains an archive of requests. Immutable except when embedded in
// a WritableArchive.
// Fields are exported to enabled JSON encoding.
//
//easyjson:json
type Archive struct {
	// Requests maps host(url) => url => []request.
	// The two-level mapping makes it easier to search for similar requests.
	// There may be multiple requests for a given URL.
	Requests map[string]map[string][]*ArchivedRequest
	// Maps host string to DER encoded certs.
	Certs map[string][]byte
	// Maps host string to the negotiated protocol. eg. "http/1.1" or "h2"
	// If absent, will default to "http/1.1".
	NegotiatedProtocol map[string]string
	// The time seed that was used to initialize deterministic.js.
	DeterministicTimeSeedMs int64
	// When an incoming request matches multiple recorded responses, whether to
	// serve the responses in the chronological sequence in which wpr_go
	// recorded them.
	ServeResponseInChronologicalSequence bool
	// Records the current session id.
	// Archive can serve responses in chronological order. If a client wants to
	// reset the Archive to serve responses from the start, the client may do so
	// by incrementing its session id.
	CurrentSessionId uint32
	// If an incoming URL doesn't exactly match an entry in the archive,
	// skip fuzzy matching and return nothing.
	DisableFuzzyURLMatching bool
}

type MultipleArchive struct {
	Archives     []*Archive
	Transformers [][]ResponseTransformer
	Names        []string
	CurrentIndex uint32
	InitIndex    int32
	PrevIndex    int32
}

func (ma *MultipleArchive) CurrentArchive() *Archive {
	return ma.Archives[atomic.LoadUint32(&ma.CurrentIndex)]
}

func (ma *MultipleArchive) InitArchive() *Archive {
	if ma.InitIndex == -1 {
		return ma.CurrentArchive()
	} else {
		return ma.Archives[ma.InitIndex]
	}
}

func (ma *MultipleArchive) PrevArchive() *Archive {
	prevIndex := atomic.LoadInt32(&ma.PrevIndex)

	if prevIndex == -1 {
		return ma.CurrentArchive()
	} else {
		return ma.Archives[prevIndex]
	}
}

func (ma *MultipleArchive) CurrentTransformers() []ResponseTransformer {
	return ma.Transformers[atomic.LoadUint32(&ma.CurrentIndex)]
}

func (ma *MultipleArchive) CurrentName() string {
	return ma.Names[atomic.LoadUint32(&ma.CurrentIndex)]
}

func (ma *MultipleArchive) ChangeArchive(nextName string) {
	nextIndex := -1

	for i, name := range ma.Names {
		if nextName == name {
			nextIndex = i
			break
		}
	}

	if nextIndex != -1 {
		currentIndex := atomic.LoadUint32(&ma.CurrentIndex)

		atomic.StoreInt32(&ma.PrevIndex, int32(currentIndex))
		atomic.StoreUint32(&ma.CurrentIndex, uint32(nextIndex))
	}
}

func (ma *MultipleArchive) FindHostTlsConfig(host string) ([]byte, string, error) {
	derBytes, negotiatedProtocol, err := ma.CurrentArchive().FindHostTlsConfig(host)

	if err != nil {
		currentIndex := atomic.LoadUint32(&ma.CurrentIndex)

		for i, archive := range ma.Archives {
			if uint32(i) == currentIndex {
				continue
			}

			derBytes, negotiatedProtocol, err = archive.FindHostTlsConfig(host)

			if err == nil {
				break
			}
		}
	}

	return derBytes, negotiatedProtocol, err
}

func newArchive() Archive {
	return Archive{Requests: make(map[string]map[string][]*ArchivedRequest)}
}

func prepareArchiveForReplay(a *Archive) {
	// Initialize the session id mechanism that Archive uses to keep state
	// information about clients.
	a.CurrentSessionId = 1
}

// OpenArchive opens an archive file previously written by OpenWritableArchive.
func OpenArchive(path string) (*Archive, error) {
	f, err := os.Open(path)

	if err != nil {
		return nil, fmt.Errorf("could not open %s: %v", path, err)
	}

	defer f.Close()

	gz, err := gzip.NewReader(f)

	if err != nil {
		return nil, fmt.Errorf("gunzip failed: %v", err)
	}

	defer gz.Close()

	a := newArchive()

	if err := easyjson.UnmarshalFromReader(gz, &a); err != nil {
		return nil, fmt.Errorf("json unmarshal failed: %v", err)
	}

	prepareArchiveForReplay(&a)
	return &a, nil
}

// ForEach applies f to all requests in the archive.
func (a *Archive) ForEach(f func(req *http.Request, resp *http.Response, dur time.Duration) error) error {
	for _, urlmap := range a.Requests {
		for urlString, requests := range urlmap {
			fullURL, _ := url.Parse(urlString)
			for index, archivedRequest := range requests {
				req, resp, err := archivedRequest.unmarshal(fullURL.Scheme)
				if err != nil {
					log.Printf("Error unmarshaling request #%d for %s: %v", index, urlString, err)
					continue
				}
				if err := f(req, resp, archivedRequest.Duration); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Returns the der encoded cert and negotiated protocol.
func (a *Archive) FindHostTlsConfig(host string) ([]byte, string, error) {
	if cert, ok := a.Certs[host]; ok {
		return cert, a.findHostNegotiatedProtocol(host), nil
	}
	return nil, "", ErrNotFound
}

func (a *Archive) findHostNegotiatedProtocol(host string) string {
	if negotiatedProtocol, ok := a.NegotiatedProtocol[host]; ok {
		return negotiatedProtocol
	}
	return "http/1.1"
}

func assertCompleteURL(url *url.URL) {
	if url.Host == "" || url.Scheme == "" {
		log.Printf("Missing host and scheme: %v\n", url)
		os.Exit(1)
	}
}

// FindRequest searches for the given request in the archive.
// Returns ErrNotFound if the request could not be found.
//
// Does not use the request body, but reads the request body to
// prevent WPR from issuing a Connection Reset error when
// handling large upload requests.
// (https://bugs.chromium.org/p/chromium/issues/detail?id=1215668)
//
// TODO: conditional requests
func (a *Archive) FindRequest(req *http.Request) (*http.Request, *http.Response, time.Duration, error) {
	// Clear the input channel on large uploads to prevent WPR
	// from resetting the connection, and causing the upload
	// to fail.
	// Large upload is an uncommon scenario for WPR users. To
	// avoid exacting an overhead on every request, restrict
	// the operation to large uploads only (size > 1MB).
	if req.Body != nil &&
		(strings.EqualFold("POST", req.Method) || strings.EqualFold("PUT", req.Method)) &&
		req.ContentLength > 2<<20 {
		buf := make([]byte, 1024)
		for {
			_, read_err := req.Body.Read(buf)
			if read_err == io.EOF {
				break
			}
		}
	}

	if strings.Contains(req.URL.Host, ".safeframe.googlesyndication.com") ||
		strings.Contains(req.URL.Host, ".googlevideo.com") {
		hostParts := strings.Split(req.URL.Host, ".")

		req.URL.Host = strings.Join(hostParts[1:], ".")
		req.Host = req.URL.Host

		q := req.URL.Query()
		q.Add("random", hostParts[0])

		req.URL.RawQuery = q.Encode()
	}

	hostMap := a.Requests[req.Host]
	if len(hostMap) == 0 {
		return nil, nil, 0, ErrNotFound
	}

	// Exact match. Note that req may be relative, but hostMap keys are always absolute.
	assertCompleteURL(req.URL)
	reqUrl := req.URL.String()

	if len(hostMap[reqUrl]) > 0 {
		return a.findBestMatchInArchivedRequestSet(req, hostMap[reqUrl])
	}

	// For all URLs with a matching path, pick the URL that has the most matching query parameters.
	// The match ratio is defined to be 2*M/T, where
	//   M = number of matches x where a.Query[x]=b.Query[x]
	//   T = sum(len(a.Query)) + sum(len(b.Query))
	aq := req.URL.Query()

	var bestURL string
	var bestURLs []string // For debugging fuzzy matching
	var bestRatio float64

	for ustr := range hostMap {
		u, err := url.Parse(ustr)

		if err != nil {
			continue
		}

		var prefix string

		if IsSubdomain("amazon.com", req.Host) && strings.HasPrefix(req.URL.Path, "/s/") {
			prefix = "/s/"
		}

		if prefix != "" {
			if !strings.HasPrefix(u.Path, prefix) {
				continue
			}
		} else if u.Path != req.URL.Path {
			continue
		}

		bq := u.Query()
		m := 1
		t := len(aq) + len(bq)

		for k, v := range aq {
			inc := 1

			// Query parameters with name "q" are normally
			// search related. Increase the weight of equality
			// in this case
			if k == "q" {
				inc = 10
			}

			if k == "field-keywords" && IsSubdomain("amazon.com", req.Host) {
				inc = 10
			}

			if k == "range" && u.Path == "/videoplayback" {
				bv, ok := bq[k]

				if !ok {
					continue
				}

				aRange := strings.Split(v[0], "-")
				bRange := strings.Split(bv[0], "-")

				startEqual := false
				endEqual := false

				if aRange[0] == bRange[0] {
					startEqual = true
				}

				if len(aRange) == 2 && len(bRange) == 2 &&
					aRange[1] == bRange[1] {
					endEqual = true
				}

				if startEqual && endEqual {
					m += 300
					continue
				} else if startEqual {
					m += 200
					continue
				}
			}

			if reflect.DeepEqual(v, bq[k]) {
				m += inc
			}
		}

		ratio := 2 * float64(m) / float64(t)

		if ratio > bestRatio {
			bestURLs = nil
		}

		bestURLs = append(bestURLs, bestURL)

		if ratio > bestRatio ||
			// Map iteration order is non-deterministic, so we must break ties.
			(ratio == bestRatio && ustr < bestURL) {
			bestURL = ustr
			bestRatio = ratio
		}
	}

	if bestURL == "" && !IsSubdomain("bing.com", req.Host) {
		bestDistance := math.MaxInt32

		for ustr := range hostMap {
			u, err := url.Parse(ustr)

			if err != nil {
				continue
			}

			distance := LevenshteinDistance(req.URL.Path, u.Path)

			if distance < bestDistance {
				bestDistance = distance
				bestURL = ustr
			}
		}
	}

	if bestURL != "" && !a.DisableFuzzyURLMatching {
		return a.findBestMatchInArchivedRequestSet(req, hostMap[bestURL])
	} else if a.DisableFuzzyURLMatching {
		logStr := "No exact match found for %s.\nFuzzy matching would have returned one of the following %d matches:\n%v\n"

		if len(bestURLs) > 0 {
			logStr += "\n"
		}

		log.Printf(logStr, reqUrl, len(bestURLs), strings.Join(bestURLs[:], "\n"))
	}

	return nil, nil, 0, ErrNotFound
}

// Given an incoming request and a set of matches in the archive, identify the best match,
// based on request headers.
func (a *Archive) findBestMatchInArchivedRequestSet(
	incomingReq *http.Request,
	archivedReqs []*ArchivedRequest) (
	*http.Request, *http.Response, time.Duration, error) {
	scheme := incomingReq.URL.Scheme

	if len(archivedReqs) == 0 {
		return nil, nil, 0, ErrNotFound
	} else if len(archivedReqs) == 1 {
		archivedReq, archivedResp, err := archivedReqs[0].unmarshal(scheme)
		if err != nil {
			log.Println("Error unmarshaling request")
			return nil, nil, 0, err
		}
		return archivedReq, archivedResp, archivedReqs[0].Duration, err
	}

	// There can be multiple requests with the same URL string. If that's the
	// case, break the tie by the number of headers that match.
	var bestMatch RequestMatch
	var bestInSequenceMatch RequestMatch

	chronologicalSequenceComplete := true

	for _, r := range archivedReqs {
		archivedReq, archivedResp, err := r.unmarshal(scheme)
		if err != nil {
			log.Println("Error unmarshaling request")
			continue
		}

		// Skip this archived request if the request methods does not match that
		// of the incoming request.
		if archivedReq.Method != incomingReq.Method {
			continue
		}

		// Count the number of header matches
		numMatchingHeaders := 1
		numTotalHeaders := len(incomingReq.Header) + len(archivedReq.Header)
		for key, val := range archivedReq.Header {
			if reflect.DeepEqual(val, incomingReq.Header[key]) {
				numMatchingHeaders++
			}
		}
		// Note that since |m| starts from 1. The ratio will be more than 0
		// even if no header matches.
		ratio := 2 * float64(numMatchingHeaders) / float64(numTotalHeaders)

		if a.ServeResponseInChronologicalSequence &&
			r.LastServedSessionId != a.CurrentSessionId &&
			(ratio > bestInSequenceMatch.MatchRatio ||
				(ratio == bestInSequenceMatch.MatchRatio &&
					Is2xxOr3xx(archivedResp) &&
					!Is2xxOr3xx(bestInSequenceMatch.Response))) {
			bestInSequenceMatch.SetMatch(r, archivedReq, archivedResp, ratio)
			chronologicalSequenceComplete = false
		}
		if ratio > bestMatch.MatchRatio ||
			(ratio == bestMatch.MatchRatio &&
				Is2xxOr3xx(archivedResp) &&
				!Is2xxOr3xx(bestMatch.Response)) {
			bestMatch.SetMatch(r, archivedReq, archivedResp, ratio)
		}
	}

	if a.ServeResponseInChronologicalSequence &&
		chronologicalSequenceComplete {
		r := archivedReqs[len(archivedReqs)-1]

		archivedReq, archivedResp, err := r.unmarshal(scheme)

		if err == nil &&
			(archivedReq.Method == incomingReq.Method) {
			bestInSequenceMatch.SetMatch(r, archivedReq, archivedResp, 0)
		}
	}

	if a.ServeResponseInChronologicalSequence &&
		bestInSequenceMatch.Match != nil {
		bestInSequenceMatch.Match.LastServedSessionId = a.CurrentSessionId
		dur := bestInSequenceMatch.Match.Duration

		return bestInSequenceMatch.Request, bestInSequenceMatch.Response, dur, nil
	} else if bestMatch.Match != nil {
		bestMatch.Match.LastServedSessionId = a.CurrentSessionId
		dur := bestMatch.Match.Duration

		return bestMatch.Request, bestMatch.Response, dur, nil
	}

	return nil, nil, 0, ErrNotFound
}

type AddMode int

const (
	AddModeAppend            AddMode = 0
	AddModeOverwriteExisting AddMode = 1
	AddModeSkipExisting      AddMode = 2
)

func (a *Archive) addArchivedRequest(req *http.Request, resp *http.Response, dur time.Duration, mode AddMode) error {
	// Always use the absolute URL in this mapping.
	assertCompleteURL(req.URL)
	archivedRequest, err := serializeRequest(req, resp, dur)
	if err != nil {
		return err
	}

	if a.Requests[req.Host] == nil {
		a.Requests[req.Host] = make(map[string][]*ArchivedRequest)
	}

	urlStr := req.URL.String()
	requests := a.Requests[req.Host][urlStr]
	if mode == AddModeAppend {
		requests = append(requests, archivedRequest)
	} else if mode == AddModeOverwriteExisting {
		log.Printf("Overwriting existing request")
		requests = []*ArchivedRequest{archivedRequest}
	} else if mode == AddModeSkipExisting {
		if requests != nil {
			log.Printf("Skipping existing request: %s", urlStr)
			return nil
		}
		requests = append(requests, archivedRequest)
	}
	a.Requests[req.Host][urlStr] = requests
	return nil
}

// Start a new replay session so that the archive serves responses from the start.
// If an archive contains multiple identical requests with different responses, the archive
// can serve the responses in chronological order. This function resets the archive serving
// order to the start.
func (a *Archive) StartNewReplaySession() {
	a.CurrentSessionId++
}

// Edit iterates over all requests in the archive. For each request, it calls f to
// edit the request. If f returns a nil pair, the request is deleted.
// The edited archive is returned, leaving the current archive is unchanged.
func (a *Archive) Edit(edit func(req *http.Request, resp *http.Response) (*http.Request, *http.Response, error)) (*Archive, error) {
	clone := newArchive()
	err := a.ForEach(func(oldReq *http.Request, oldResp *http.Response, dur time.Duration) error {
		newReq, newResp, err := edit(oldReq, oldResp)
		if err != nil {
			return err
		}
		if newReq == nil || newResp == nil {
			if newReq != nil || newResp != nil {
				panic("programming error: newReq/newResp must both be nil or non-nil")
			}
			return nil
		}
		// TODO: allow changing scheme or protocol?
		return clone.addArchivedRequest(newReq, newResp, dur, AddModeAppend)
	})
	if err != nil {
		return nil, err
	}
	return &clone, nil
}

// Merge adds all the request of the provided archive to the receiver.
func (a *Archive) Merge(youtubeOnly bool, other *Archive) error {
	var numAddedRequests = 0
	var numSkippedRequests = 0

	var err error

	if youtubeOnly {
		err = other.ForEach(func(req *http.Request, resp *http.Response, dur time.Duration) error {
			if req.URL.Host != "googlevideo.com" {
				return nil
			}

			foundReq, _, _, notFoundErr := a.FindRequest(req)

			if notFoundErr == ErrNotFound {
				if err := a.addArchivedRequest(req, resp, dur, AddModeAppend); err != nil {
					return err
				}

				numAddedRequests++
			} else {
				aq := req.URL.Query()
				bq := foundReq.URL.Query()

				if aq.Get("range") != bq.Get("range") || aq.Get("mime") != bq.Get("mime") {
					if err := a.addArchivedRequest(req, resp, dur, AddModeAppend); err != nil {
						return err
					}

					numAddedRequests++
				} else {
					numSkippedRequests++
				}
			}

			return nil
		})
	} else {
		err = other.ForEach(func(req *http.Request, resp *http.Response, dur time.Duration) error {
			foundReq, _, _, notFoundErr := a.FindRequest(req)

			if notFoundErr == ErrNotFound || req.URL.String() != foundReq.URL.String() {
				if err := a.addArchivedRequest(req, resp, dur, AddModeAppend); err != nil {
					return err
				}

				numAddedRequests++
			} else {
				numSkippedRequests++
			}

			return nil
		})
	}

	log.Printf("Merged requests: added=%d duplicates=%d \n", numAddedRequests, numSkippedRequests)

	return err
}

// Trim iterates over all requests in the archive. For each request, it calls f
// to see if the request should be removed the archive.
// The trimmed archive is returned, leaving the current archive unchanged.
func (a *Archive) Trim(trimMatch func(req *http.Request, resp *http.Response) (bool, error)) (*Archive, error) {
	var numRemovedRequests = 0
	clone := newArchive()
	err := a.ForEach(func(req *http.Request, resp *http.Response, dur time.Duration) error {
		trimReq, err := trimMatch(req, resp)
		if err != nil {
			return err
		}
		if trimReq {
			numRemovedRequests++
		} else {
			clone.addArchivedRequest(req, resp, dur, AddModeAppend)
		}
		return nil
	})
	log.Printf("Trimmed requests: removed=%d", numRemovedRequests)
	if err != nil {
		return nil, err
	}
	return &clone, nil
}

// Add the result of a get request to the receiver.
func (a *Archive) Add(method string, urlString string, mode AddMode) error {
	req, err := http.NewRequest(method, urlString, nil)
	if err != nil {
		return fmt.Errorf("Error creating request object: %v", err)
	}

	url, _ := url.Parse(urlString)
	// Print a warning for duplicate requests since the replay server will only
	// return the first found response.
	if mode == AddModeAppend || mode == AddModeSkipExisting {
		if foundReq, _, _, notFoundErr := a.FindRequest(req); notFoundErr != ErrNotFound {
			if foundReq.URL.String() == url.String() {
				if mode == AddModeSkipExisting {
					log.Printf("Skipping existing request: %s %s", req.Method, urlString)
					return nil
				}
				log.Printf("Adding duplicate request:")
			}
		}
	}

	t0 := time.Now()
	resp, err := http.DefaultClient.Do(req)
	t1 := time.Now()

	if err != nil {
		return fmt.Errorf("Error fetching url: %v", err)
	}

	if err = a.addArchivedRequest(req, resp, t1.Sub(t0), mode); err != nil {
		return err
	}

	fmt.Printf("Added request: (%s %s) %s\n", req.Method, resp.Status, urlString)
	return nil
}

// Serialize serializes this archive to the given writer.
func (a *Archive) Serialize(w io.Writer) error {
	gz := gzip.NewWriter(w)
	if err := json.NewEncoder(gz).Encode(a); err != nil {
		return fmt.Errorf("json marshal failed: %v", err)
	}
	return gz.Close()
}

// WriteableArchive wraps an Archive with writable methods for recording.
// The file is not flushed until Close is called. All methods are thread-safe.
type WritableArchive struct {
	Archive
	f  *os.File
	mu sync.Mutex
}

type MultipleWritableArchive struct {
	IsDir bool
	Dir   string

	WritableArchives []*WritableArchive
	Transformers     []ResponseTransformer
	Names            []string
	CurrentIndex     uint32

	mu sync.Mutex
}

func (mwa *MultipleWritableArchive) CurrentArchive() *WritableArchive {
	return mwa.WritableArchives[atomic.LoadUint32(&mwa.CurrentIndex)]
}

func (mwa *MultipleWritableArchive) CurrentTransformers() []ResponseTransformer {
	return mwa.Transformers
}

func (mwa *MultipleWritableArchive) CurrentName() string {
	return mwa.Names[atomic.LoadUint32(&mwa.CurrentIndex)]
}

func (mwa *MultipleWritableArchive) ChangeArchive(nextName string) {
	mwa.mu.Lock()
	defer mwa.mu.Unlock()

	nextIndex := -1

	for i, name := range mwa.Names {
		if nextName == name {
			nextIndex = i
			break
		}
	}

	if nextIndex != -1 {
		atomic.StoreUint32(&mwa.CurrentIndex, uint32(nextIndex))
		return
	}

	if mwa.Names[0] == "default" {
		mwa.Names[0] = nextName
		return
	}

	if mwa.IsDir {
		archiveFileName := filepath.Join(
			mwa.Dir,
			fmt.Sprintf("%s.json.gz", nextName),
		)

		archive, err := OpenWritableArchive(archiveFileName)

		if err != nil {
			log.Println(err)
			os.Exit(1)
		}

		log.Printf("Opened archive %s", archiveFileName)

		// Reuse starting time seed
		archive.DeterministicTimeSeedMs = mwa.WritableArchives[0].DeterministicTimeSeedMs

		mwa.WritableArchives = append(mwa.WritableArchives, archive)
		mwa.Names = append(mwa.Names, nextName)

		atomic.StoreUint32(&mwa.CurrentIndex, uint32(len(mwa.WritableArchives)-1))
	}
}

func (mwa *MultipleWritableArchive) Close() error {
	mwa.mu.Lock()
	defer mwa.mu.Unlock()

	for i, a := range mwa.WritableArchives {
		log.Printf("Writing archive %s", mwa.Names[i])

		name := a.f.Name()

		if err := a.Close(); err != nil {
			return err
		}

		if filepath.Base(name) == "default.json.gz" {
			newName := filepath.Join(
				filepath.Dir(name),
				fmt.Sprintf("%s.json.gz", mwa.Names[i]),
			)

			err := os.Rename(
				name,
				newName,
			)

			if err != nil {
				return err
			}
		}
	}

	return nil
}

// OpenWritableArchive opens an archive file for writing.
// The output is gzipped JSON.
func OpenWritableArchive(path string) (*WritableArchive, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("could not open %s: %v", path, err)
	}
	return &WritableArchive{Archive: newArchive(), f: f}, nil
}

// RecordRequest records a request/response pair in the archive.
func (a *WritableArchive) RecordRequest(req *http.Request, resp *http.Response, dur time.Duration) error {
	if strings.Contains(req.URL.Host, ".safeframe.googlesyndication.com") ||
		strings.Contains(req.URL.Host, ".googlevideo.com") {
		hostParts := strings.Split(req.URL.Host, ".")

		req.URL.Host = strings.Join(hostParts[1:], ".")
		req.Host = req.URL.Host

		q := req.URL.Query()
		q.Add("random", hostParts[0])

		req.URL.RawQuery = q.Encode()
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	return a.addArchivedRequest(req, resp, dur, AddModeAppend)
}

// RecordTlsConfig records the cert used and protocol negotiated for a host.
func (a *WritableArchive) RecordTlsConfig(host string, der_bytes []byte, negotiatedProtocol string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.Certs == nil {
		a.Certs = make(map[string][]byte)
	}
	if _, ok := a.Certs[host]; !ok {
		a.Certs[host] = der_bytes
	}
	if a.NegotiatedProtocol == nil {
		a.NegotiatedProtocol = make(map[string]string)
	}
	a.NegotiatedProtocol[host] = negotiatedProtocol
}

// Close flushes the the archive and closes the output file.
func (a *WritableArchive) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer func() { a.f = nil }()
	if a.f == nil {
		return errors.New("already closed")
	}

	if err := a.Serialize(a.f); err != nil {
		return err
	}
	return a.f.Close()
}
