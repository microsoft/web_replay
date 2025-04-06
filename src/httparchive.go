// Modifications Copyright (c) Microsoft Corporation.
// Licensed under the BSD-3-Clause license.
//
// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Program httparchive prints information about archives saved by record.
package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/microsoft/web_replay/src/webreplay"
	"github.com/urfave/cli/v2"
)

const usage = "%s [ls|cat|edit|merge|add|addAll|trim|header|cookiesRemove|idleTimeout|certsUpdate] [options] archive_file [output_file] [url]"

type Config struct {
	method, host, fullPath                                           string
	statusCode                                                       int
	decodeResponseBody, skipExisting, overwriteExisting, invertMatch bool
	youtubeOnly                                                      bool
}

func (cfg *Config) DefaultFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "command",
			Value:       "",
			Usage:       "Only show URLs matching this HTTP method.",
			Destination: &cfg.method,
		},
		&cli.StringFlag{
			Name:        "host",
			Value:       "",
			Usage:       "Only show URLs matching this host.",
			Destination: &cfg.host,
		},
		&cli.StringFlag{
			Name:        "full_path",
			Value:       "",
			Usage:       "Only show URLs matching this full path.",
			Destination: &cfg.fullPath,
		},
		&cli.IntFlag{
			Name:        "status_code",
			Value:       0,
			Usage:       "Only show URLs matching this response status code.",
			Destination: &cfg.statusCode,
		},
		&cli.BoolFlag{
			Name:        "decode_response_body",
			Usage:       "Decode/encode response body according to Content-Encoding header.",
			Destination: &cfg.decodeResponseBody,
		},
	}
}

func (cfg *Config) AddFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "skip-existing",
			Usage:       "Skip over existing urls in the archive",
			Destination: &cfg.skipExisting,
		},
		&cli.BoolFlag{
			Name:        "overwrite-existing",
			Usage:       "Overwrite existing urls in the archive",
			Destination: &cfg.overwriteExisting,
		},
	}
}

func (cfg *Config) MergeFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "youtube_only",
			Usage:       "Only merge distinct googlevideo requests",
			Destination: &cfg.youtubeOnly,
		},
	}
}

func (cfg *Config) TrimFlags() []cli.Flag {
	return append([]cli.Flag{
		&cli.BoolFlag{
			Name:        "invert-match",
			Usage:       "Trim away any urls that DON'T match in the archive",
			Destination: &cfg.invertMatch,
		},
	}, cfg.DefaultFlags()...)
}

func (cfg *Config) requestEnabled(req *http.Request, resp *http.Response) bool {
	if cfg.method != "" && strings.ToUpper(cfg.method) != req.Method {
		return false
	}
	if cfg.host != "" && cfg.host != req.Host {
		return false
	}
	if cfg.fullPath != "" && cfg.fullPath != req.URL.Path {
		return false
	}
	if cfg.statusCode != 0 && cfg.statusCode != resp.StatusCode {
		return false
	}
	return true
}

type ListOption int

const (
	LIST_REQ ListOption = iota
	LIST_HEADER
	LIST_HEADER_BODY
)

func list(cfg *Config, a *webreplay.Archive, option ListOption) error {
	return a.ForEach(func(req *http.Request, resp *http.Response, dur time.Duration) error {
		if !cfg.requestEnabled(req, resp) {
			return nil
		}
		if option == LIST_REQ {
			fmt.Fprintf(os.Stdout, "%s %s %s %s\n", req.Method, req.Host, req.URL, resp.Status)
		} else {
			fmt.Fprint(os.Stdout, "----------------------------------------\n")
			if option == LIST_HEADER {
				req.Header.Write(os.Stdout)
			} else {
				req.Write(os.Stdout)
			}
			fmt.Fprint(os.Stdout, "\n")
			err := webreplay.DecompressResponse(resp)
			if err != nil {
				return fmt.Errorf("Unable to decompress body:\n%v", err)
			}
			if option == LIST_HEADER {
				resp.Header.Write(os.Stdout)
			} else {
				resp.Write(os.Stdout)
			}
			fmt.Fprint(os.Stdout, "\n")
		}
		return nil
	})
}

func trim(cfg *Config, a *webreplay.Archive, outfile string) error {
	newA, err := a.Trim(func(req *http.Request, resp *http.Response) (bool, error) {
		// If req matches and invertMatch -> keep match
		// If req doesn't match and !invertMatch -> keep match
		// Otherwise, trim match
		if cfg.requestEnabled(req, resp) == cfg.invertMatch {
			fmt.Printf("Keeping request: host=%s uri=%s\n", req.Host, req.URL.String())
			return false, nil
		} else {
			fmt.Printf("Trimming request: host=%s uri=%s\n", req.Host, req.URL.String())
			return true, nil
		}
	})
	if err != nil {
		return fmt.Errorf("error editing archive:\n%v", err)
	}
	return writeArchive(newA, outfile)
}

func edit(cfg *Config, a *webreplay.Archive, outfile string) error {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		fmt.Printf("Warning: EDITOR not specified, using default.\n")
		editor = "vi"
	}

	marshalForEdit := func(w io.Writer, req *http.Request, resp *http.Response) error {
		// WriteProxy writes absolute URI in the Start line including the
		// scheme and host. It is necessary for unmarshaling later.
		if err := req.WriteProxy(w); err != nil {
			return err
		}
		if cfg.decodeResponseBody {
			if err := webreplay.DecompressResponse(resp); err != nil {
				return fmt.Errorf("couldn't decompress body: %v", err)
			}
		}
		return resp.Write(w)
	}

	unmarshalAfterEdit := func(r io.Reader) (*http.Request, *http.Response, error) {
		br := bufio.NewReader(r)
		req, err := http.ReadRequest(br)
		if err != nil {
			return nil, nil, fmt.Errorf("couldn't unmarshal request: %v", err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			if req.Body != nil {
				req.Body.Close()
			}
			return nil, nil, fmt.Errorf("couldn't unmarshal response: %v", err)
		}
		if cfg.decodeResponseBody {
			// Compress body back according to Content-Encoding
			if err := compressResponse(resp); err != nil {
				return nil, nil, fmt.Errorf("couldn't compress response: %v", err)
			}
		}
		// Read resp.Body into a buffer since the tmpfile is about to be deleted.
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("couldn't unmarshal response body: %v", err)
		}
		resp.Body = ioutil.NopCloser(bytes.NewReader(body))
		return req, resp, nil
	}

	newA, err := a.Edit(func(req *http.Request, resp *http.Response) (*http.Request, *http.Response, error) {
		if !cfg.requestEnabled(req, resp) {
			return req, resp, nil
		}
		fmt.Printf("Editing request: host=%s uri=%s\n", req.Host, req.URL.String())
		// Serialize the req/resp to a temporary file, let the user edit that file, then
		// de-serialize and return the result. Repeat until de-serialization succeeds.
		for {
			tmpf, err := ioutil.TempFile("", "httparchive_edit_request")
			if err != nil {
				return nil, nil, err
			}
			tmpname := tmpf.Name()
			defer os.Remove(tmpname)
			if err := marshalForEdit(tmpf, req, resp); err != nil {
				tmpf.Close()
				return nil, nil, err
			}
			if err := tmpf.Close(); err != nil {
				return nil, nil, err
			}
			// Edit this file.
			cmd := exec.Command(editor, tmpname)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return nil, nil, fmt.Errorf("Error running %s %s: %v", editor, tmpname, err)
			}
			// Reload.
			tmpf, err = os.Open(tmpname)
			if err != nil {
				return nil, nil, err
			}
			defer tmpf.Close()
			newReq, newResp, err := unmarshalAfterEdit(tmpf)
			if err != nil {
				fmt.Printf("Error in editing request. Try again: %v\n", err)
				continue
			}
			return newReq, newResp, nil
		}
	})
	if err != nil {
		return fmt.Errorf("error editing archive:\n%v", err)
	}

	return writeArchive(newA, outfile)
}

func writeArchive(archive *webreplay.Archive, outfile string) error {
	outf, err := os.OpenFile(outfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(0660))
	if err != nil {
		return fmt.Errorf("error opening output file %s:\n%v", outfile, err)
	}
	err0 := archive.Serialize(outf)
	err1 := outf.Close()
	if err0 != nil || err1 != nil {
		if err0 == nil {
			err0 = err1
		}
		return fmt.Errorf("error writing edited archive to %s:\n%v", outfile, err0)
	}
	fmt.Printf("Wrote edited archive to %s\n", outfile)
	return nil
}

func merge(cfg *Config, archive *webreplay.Archive, input *webreplay.Archive, outfile string) error {
	if err := archive.Merge(cfg.youtubeOnly, input); err != nil {
		return fmt.Errorf("Merge archives failed: %v", err)
	}

	return writeArchive(archive, outfile)
}

func addUrl(cfg *Config, archive *webreplay.Archive, urlString string) error {
	addMode := webreplay.AddModeAppend
	if cfg.skipExisting {
		addMode = webreplay.AddModeSkipExisting
	} else if cfg.overwriteExisting {
		addMode = webreplay.AddModeOverwriteExisting
	}
	if err := archive.Add("GET", urlString, addMode); err != nil {
		return fmt.Errorf("Error adding request: %v", err)
	}
	return nil
}

func add(cfg *Config, archive *webreplay.Archive, outfile string, urls []string) error {
	for _, urlString := range urls {
		if err := addUrl(cfg, archive, urlString); err != nil {
			return err
		}
	}
	return writeArchive(archive, outfile)
}

func addAll(cfg *Config, archive *webreplay.Archive, outfile string, inputFilePath string) error {
	f, err := os.OpenFile(inputFilePath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return fmt.Errorf("open file error: %v", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		urlString := sc.Text() // GET the line string
		if err := addUrl(cfg, archive, urlString); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("scan file error: %v", err)
	}

	return writeArchive(archive, outfile)
}

func cookiesRemove(cfg *Config, archive *webreplay.Archive, outfile string) error {
	newA, err := archive.Edit(func(req *http.Request, resp *http.Response) (*http.Request, *http.Response, error) {
		req.Header.Del("Cookie")
		req.Header.Del("Set-Cookie")

		resp.Header.Del("Cookie")
		resp.Header.Del("Set-Cookie")

		return req, resp, nil
	})

	// Update the original archive requests to retain the remaining data
	archive.Requests = newA.Requests

	if err != nil {
		return fmt.Errorf("error editing archive:\n%v", err)
	}

	return writeArchive(archive, outfile)
}

func isConnClosed(conn *tls.Conn) bool {
	one := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(1 * time.Nanosecond))
	_, err := conn.Read(one)

	if err == io.EOF {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	return err != nil
}

func getIdleTimeout(serverName string) (time.Duration, error) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		fmt.Sprintf("%s:443", serverName),
		&tls.Config{InsecureSkipVerify: true},
	)

	if err != nil {
		return 0, fmt.Errorf("error dialing connection: %v", err)
	}

	defer conn.Close()

	var elapsed time.Duration
	startTime := time.Now()
	lastPrintedTime := startTime

	for {
		elapsed = time.Since(startTime)
		time.Sleep(1 * time.Second)
		if isConnClosed(conn) {
			break
		}
		if time.Since(lastPrintedTime) >= 5*time.Minute {
			fmt.Printf("long connection: %s %v\n", serverName, elapsed)
			lastPrintedTime = time.Now()
		}
		if elapsed >= 1*time.Hour {
			fmt.Printf("ending non-stop connection: %s\n", serverName)
			break
		}
	}

	fmt.Println(serverName, elapsed)
	return elapsed, nil
}

func getIdleTimeouts(serverNames map[string]string) map[string]time.Duration {
	idleTimeouts := make(map[string]time.Duration)
	sem := make(chan struct{}, 100)

	var mu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(len(serverNames))

	fmt.Printf("Obtaining idle timeouts for %d servers\n", len(serverNames))

	for serverName, _ := range serverNames {
		sem <- struct{}{}
		go func(serverName string) {
			defer func() { <-sem }()
			defer wg.Done()

			idleTimeout, err := getIdleTimeout(serverName)

			if err != nil {
				fmt.Printf("error finding idle timeout for %s: %v\n", serverName, err)
			}

			mu.Lock()
			idleTimeouts[serverName] = idleTimeout
			mu.Unlock()
		}(serverName)
	}

	wg.Wait()
	close(sem)

	return idleTimeouts
}

func idleTimeoutRead(idle string) (map[string]time.Duration, error) {
	idleTimeoutFile, err := os.Open(idle)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %s", idle)
	}
	defer idleTimeoutFile.Close()

	idleTimeoutBytes, err := io.ReadAll(idleTimeoutFile)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %s", idle)
	}

	var temp map[string]int

	if err := json.Unmarshal(idleTimeoutBytes, &temp); err != nil {
		return nil, fmt.Errorf("error reading json: %s", err)
	}

	idleTimeouts := make(map[string]time.Duration)

	for k, v := range temp {
		idleTimeouts[k] = time.Duration(v) * time.Millisecond
	}

	return idleTimeouts, nil
}

func idleTimeout(cfg *Config, in string, idle string, out string) error {
	inFileInfo, err := os.Stat(in)

	if err != nil {
		return fmt.Errorf("error opening archive: %s", in)
	}

	idleTimeouts, err := idleTimeoutRead(idle)
	if err != nil {
		return fmt.Errorf("error reading idle timeouts: %s", in)
	}

	type wArchive struct {
		a       *webreplay.Archive
		outFile string
	}

	archives := make([]*wArchive, 0)
	serverNames := make(map[string]string)

	if inFileInfo.IsDir() {
		entries, err := os.ReadDir(in)

		if err != nil {
			return fmt.Errorf("error reading directory: %s", in)
		}

		if _, err := os.Stat(out); os.IsNotExist(err) {
			err := os.MkdirAll(out, os.ModePerm)

			if err != nil {
				return fmt.Errorf("error making directory: %s", out)
			}
		}

		for _, e := range entries {
			if e.IsDir() {
				continue
			}

			inA := filepath.Join(in, e.Name())

			archive, err := webreplay.OpenArchive(inA)
			if err != nil {
				return fmt.Errorf("error opening archive: %s", inA)
			}

			archives = append(archives, &wArchive{archive, filepath.Join(out, e.Name())})

			for serverName, val := range archive.NegotiatedProtocol {
				if _, ok := serverNames[serverName]; !ok {
					serverNames[serverName] = val
				}
			}
		}
	} else {
		archive, err := webreplay.OpenArchive(in)
		if err != nil {
			return fmt.Errorf("error opening archive: %s", in)
		}

		archives = append(archives, &wArchive{archive, out})
		serverNames = archive.NegotiatedProtocol
	}

	idleTimeoutsTLS := getIdleTimeouts(serverNames)
	unassignedServers := make(map[string]bool)

	for _, archive := range archives {
		archive.a.IdleTimeouts = make(map[string]time.Duration)

		for serverName, _ := range archive.a.NegotiatedProtocol {
			if idleTimeout, ok := idleTimeouts[serverName]; ok {
				archive.a.IdleTimeouts[serverName] = idleTimeout
			} else if idleTimeout, ok := idleTimeoutsTLS[serverName]; ok {
				if idleTimeout >= 5*time.Minute {
					fmt.Printf("using tls timeout: %s %v\n", serverName, idleTimeout)
					archive.a.IdleTimeouts[serverName] = idleTimeout
				} else {
					fmt.Printf("not assigning timeout: %s %v\n", serverName, idleTimeout)
					unassignedServers[serverName] = true
				}
			} else {
				fmt.Printf("not assigning timeout: %s\n", serverName)
				unassignedServers[serverName] = true
			}
		}

		err = writeArchive(archive.a, archive.outFile)

		if err != nil {
			fmt.Printf("error writing archive: %v\n", err)
		}
	}

	if len(unassignedServers) > 0 {
		fmt.Printf("unassigned servers: %d\n", len(unassignedServers))
	}

	return nil
}

type certCtx struct {
	intCert *x509.Certificate
	intKey  crypto.PrivateKey
}

func createCertCtx() (*certCtx, error) {
	ctx := new(certCtx)

	intCertFile := "certs\\int_cert.pem"
	intKeyFile := "certs\\int_key.pem"

	// Load int certs
	fmt.Printf("Loading int cert from %v\n", intCertFile)
	fmt.Printf("Loading int key from %v\n", intKeyFile)

	intCert, err := tls.LoadX509KeyPair(intCertFile, intKeyFile)

	if err != nil {
		return nil, fmt.Errorf("error opening int cert or int key files: %v", err)
	}

	ctx.intCert, err = webreplay.GetIntCert(intCert)

	if err != nil {
		return nil, fmt.Errorf("error obtaining int certificate: %v", err)
	}

	ctx.intKey = intCert.PrivateKey

	return ctx, nil
}

func updateCertDateRange(derBytes []byte, ctx *certCtx) ([]byte, error) {
	cert, err := x509.ParseCertificate(derBytes)

	if err != nil {
		return nil, fmt.Errorf("error parsing certificate")
	}

	dt := time.Now()

	cert.NotBefore = dt.Add(-24 * time.Hour)

	// Certs cannot be valid for longer than 12 mths.
	cert.NotAfter = dt.Add(12 * 30 * 24 * time.Hour)

	return x509.CreateCertificate(rand.Reader, cert, ctx.intCert, cert.PublicKey, ctx.intKey)
}

func certsUpdateArchive(archive *webreplay.Archive, out string, ctx *certCtx) error {
	for host, derBytes := range archive.Certs {
		certBytes := webreplay.ParseDerBytes(derBytes)
		totalDerBytesNew := []byte{}

		for i := 0; i < len(certBytes); i++ {
			derBytesNew, err := updateCertDateRange(certBytes[i], ctx)

			if err != nil {
				return fmt.Errorf("error updating certificate date range")
			}

			totalDerBytesNew = append(totalDerBytesNew, derBytesNew...)
		}

		archive.Certs[host] = totalDerBytesNew
	}

	err := writeArchive(archive, out)

	if err != nil {
		return fmt.Errorf("error writing archive: %v\n", err)
	}

	return nil
}

func certsUpdate(cfg *Config, in string, out string) error {
	inFileInfo, err := os.Stat(in)

	if err != nil {
		return fmt.Errorf("error opening archive: %s", in)
	}

	ctx, err := createCertCtx()

	if err != nil {
		return fmt.Errorf("error creating certificate context")
	}

	if inFileInfo.IsDir() {
		entries, err := os.ReadDir(in)

		if err != nil {
			return fmt.Errorf("error reading directory: %s", in)
		}

		if _, err := os.Stat(out); os.IsNotExist(err) {
			err := os.MkdirAll(out, os.ModePerm)

			if err != nil {
				return fmt.Errorf("error making directory: %s", out)
			}
		}

		for _, e := range entries {
			if e.IsDir() {
				continue
			}

			inA := filepath.Join(in, e.Name())

			archive, err := webreplay.OpenArchive(inA)
			if err != nil {
				return fmt.Errorf("error opening archive: %s", inA)
			}

			err = certsUpdateArchive(archive, filepath.Join(out, e.Name()), ctx)
			if err != nil {
				return fmt.Errorf("error updating archive certificates")
			}
		}
	} else {
		archive, err := webreplay.OpenArchive(in)
		if err != nil {
			return fmt.Errorf("error opening archive: %s", in)
		}

		err = certsUpdateArchive(archive, out, ctx)
		if err != nil {
			return fmt.Errorf("error updating archive certificates")
		}

	}

	return nil
}

// compressResponse compresses resp.Body in place according to resp's Content-Encoding header.
func compressResponse(resp *http.Response) error {
	ce := strings.ToLower(resp.Header.Get("Content-Encoding"))
	if ce == "" {
		return nil
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	body, newCE, err := webreplay.CompressBody(ce, body)
	if err != nil {
		return err
	}
	if ce != newCE {
		return fmt.Errorf("can't compress body to '%s' recieved Content-Encoding: '%s'", ce, newCE)
	}
	resp.Body = ioutil.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	return nil
}

func main() {
	progName := filepath.Base(os.Args[0])
	cfg := &Config{}

	fail := func(c *cli.Context, err error) {
		fmt.Fprintf(os.Stderr, "Error:\n%v.\n\n", err)
		cli.ShowSubcommandHelp(c)
		os.Exit(1)
	}

	checkArgs := func(cmdName string, wantArgs int) func(*cli.Context) error {
		return func(c *cli.Context) error {
			if c.Args().Len() != wantArgs {
				return fmt.Errorf("Expected %d arguments but got %d", wantArgs, c.Args().Len())
			}
			return nil
		}
	}
	loadArchiveOrDie := func(c *cli.Context, arg int) *webreplay.Archive {
		archive, err := webreplay.OpenArchive(c.Args().Get(arg))
		if err != nil {
			fail(c, err)
		}
		return archive
	}

	app := cli.NewApp()
	app.Commands = []*cli.Command{
		&cli.Command{
			Name:      "ls",
			Usage:     "List the requests in an archive",
			ArgsUsage: "archive",
			Flags:     cfg.DefaultFlags(),
			Before:    checkArgs("ls", 1),
			Action: func(c *cli.Context) error {
				return list(cfg, loadArchiveOrDie(c, 0), LIST_REQ)
			},
		},
		&cli.Command{
			Name:      "header",
			Usage:     "Dump the request/response headers in an archive",
			ArgsUsage: "archive",
			Flags:     cfg.DefaultFlags(),
			Before:    checkArgs("header", 1),
			Action: func(c *cli.Context) error {
				return list(cfg, loadArchiveOrDie(c, 0), LIST_HEADER)
			},
		},
		&cli.Command{
			Name:      "cat",
			Usage:     "Dump the requests/responses in an archive",
			ArgsUsage: "archive",
			Flags:     cfg.DefaultFlags(),
			Before:    checkArgs("cat", 1),
			Action: func(c *cli.Context) error {
				return list(cfg, loadArchiveOrDie(c, 0), LIST_HEADER_BODY)
			},
		},
		&cli.Command{
			Name:      "edit",
			Usage:     "Edit the requests/responses in an archive",
			ArgsUsage: "input_archive output_archive",
			Flags:     cfg.DefaultFlags(),
			Before:    checkArgs("edit", 2),
			Action: func(c *cli.Context) error {
				return edit(cfg, loadArchiveOrDie(c, 0), c.Args().Get(1))
			},
		},
		&cli.Command{
			Name:      "merge",
			Usage:     "Merge the requests/responses of two archives",
			ArgsUsage: "base_archive input_archive output_archive",
			Flags:     cfg.MergeFlags(),
			Before:    checkArgs("merge", 3),
			Action: func(c *cli.Context) error {
				return merge(cfg, loadArchiveOrDie(c, 0), loadArchiveOrDie(c, 1), c.Args().Get(2))
			},
		},
		&cli.Command{
			Name:      "add",
			Usage:     "Add a simple GET request from the network to the archive",
			ArgsUsage: "input_archive output_archive [urls...]",
			Flags:     cfg.AddFlags(),
			Before: func(c *cli.Context) error {
				if c.Args().Len() < 3 {
					return fmt.Errorf("Expected at least 3 arguments but got %d", c.Args().Len())
				}
				return nil
			},
			Action: func(c *cli.Context) error {
				return add(cfg, loadArchiveOrDie(c, 0), c.Args().Get(1), c.Args().Tail())
			},
		},
		&cli.Command{
			Name:      "addAll",
			Usage:     "Add a simple GET request from the network to the archive",
			ArgsUsage: "input_archive output_archive urls_file",
			Flags:     cfg.AddFlags(),
			Before:    checkArgs("add", 3),
			Action: func(c *cli.Context) error {
				return addAll(cfg, loadArchiveOrDie(c, 0), c.Args().Get(1), c.Args().Get(2))
			},
		},
		&cli.Command{
			Name:      "trim",
			Usage:     "Trim the requests/responses in an archive",
			ArgsUsage: "input_archive output_archive",
			Flags:     cfg.TrimFlags(),
			Before:    checkArgs("trim", 2),
			Action: func(c *cli.Context) error {
				return trim(cfg, loadArchiveOrDie(c, 0), c.Args().Get(1))
			},
		},
		&cli.Command{
			Name:      "cookiesRemove",
			Usage:     "Remove cookie headers from requests/responses in an archive",
			ArgsUsage: "input_archive output_archive",
			Flags:     cfg.DefaultFlags(),
			Before:    checkArgs("cookiesRemove", 2),
			Action: func(c *cli.Context) error {
				return cookiesRemove(cfg, loadArchiveOrDie(c, 0), c.Args().Get(1))
			},
		},
		&cli.Command{
			Name:      "idleTimeout",
			Usage:     "Add server idle timeouts to an archive (or multiple)",
			ArgsUsage: "input_archive idle_timeouts output_archive",
			Flags:     cfg.DefaultFlags(),
			Before:    checkArgs("idleTimeout", 3),
			Action: func(c *cli.Context) error {
				return idleTimeout(cfg, c.Args().Get(0), c.Args().Get(1), c.Args().Get(2))
			},
		},
		&cli.Command{
			Name:      "certsUpdate",
			Usage:     "Update host certificates for an archive (or multiple)",
			ArgsUsage: "input_archive output_archive",
			Flags:     cfg.DefaultFlags(),
			Before:    checkArgs("certsUpdate", 2),
			Action: func(c *cli.Context) error {
				return certsUpdate(cfg, c.Args().Get(0), c.Args().Get(1))
			},
		},
	}
	app.Usage = "HTTP Archive Utils"
	app.UsageText = fmt.Sprintf(usage, progName)
	app.HideVersion = true
	app.Version = ""
	app.Writer = os.Stderr
	err := app.Run(os.Args)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
}
