// Modifications Copyright (c) Microsoft Corporation.
// Licensed under the BSD-3-Clause license.
//
// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Program wpr records and replays web traffic.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/microsoft/web_replay/src/webreplay"
	"github.com/urfave/cli/v2"
	"golang.org/x/net/http2"
)

const longUsage = `
   %s [installroot|removeroot] [options]
   %s [record|replay] [options] archive_file

   Before: Install a test root CA.
     $ GOPATH=$PWD go run src/wpr.go installroot

   To record web pages:
     1. Start this program in record mode.
        $ GOPATH=$PWD go run src/wpr.go record archive.json
     2. Load the web pages you want to record in a web browser. It is important to
        clear browser caches before this so that all subresources are requested
        from the network.
     3. Kill the process to stop recording.

   To replay web pages:
     1. Start this program in replay mode with a previously recorded archive.
        $ GOPATH=$PWD go run src/wpr.go replay archive.json
     2. Load recorded pages in a web browser. A 404 will be served for any pages or
        resources not in the recorded archive.

   After: Remove the test root CA.
     $ GOPATH=$PWD go run src/wpr.go removeroot`

type CertConfig struct {
	// Flags common to all commands.
	leafCertFiles, leafKeyFiles, intCertFile, intKeyFile string
}

type CommonConfig struct {
	// Info about this command.
	cmd cli.Command

	// Flags common to RecordCommand and ReplayCommand.
	host                                                    string
	httpPort, httpsPort, httpProxyPort, httpSecureProxyPort int
	certConfig                                              CertConfig
	injectScriptsDir                                        string

	// Computed state.
	leaf_certs []tls.Certificate
	int_cert   tls.Certificate

	outDir string
}

type RecordCommand struct {
	common CommonConfig
	cmd    cli.Command

	// Custom flags for record.
	proxyServer string
}

type ReplayCommand struct {
	common CommonConfig
	cmd    cli.Command

	// Custom flags for replay.
	rulesFile                            string
	serveResponseInChronologicalSequence bool
	quietMode                            bool
	excludesList                         string
	disableFuzzyURLMatching              bool
	disableReqDelay                      bool
	theme                                string
}

type RootCACommand struct {
	certConfig CertConfig
	installer  webreplay.Installer
	cmd        cli.Command
}

func (certCfg *CertConfig) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "https_leaf_cert_file",
			Value:       "certs\\leaf_cert_rsa.pem,certs\\leaf_cert_ecdsa.pem",
			Usage:       "File containing 1 or more comma separated PEM-encoded X509 leaf certificates to use with SSL.",
			Destination: &certCfg.leafCertFiles,
		},
		&cli.StringFlag{
			Name:        "https_leaf_key_file",
			Value:       "certs\\leaf_key_rsa.pem,certs\\leaf_key_ecdsa.pem",
			Usage:       "File containing 1 or more comma separated PEM-encoded private keys to use with SSL.",
			Destination: &certCfg.leafKeyFiles,
		},
		&cli.StringFlag{
			Name:        "https_int_cert_file",
			Value:       "certs\\int_cert.pem",
			Usage:       "Intermediate certificate file containing a PEM-encoded X509 certificate to use with SSL.",
			Destination: &certCfg.intCertFile,
		},
		&cli.StringFlag{
			Name:        "https_int_key_file",
			Value:       "certs\\int_key.pem",
			Usage:       "Intermediate key File containing a PEM-encoded private key to use with SSL.",
			Destination: &certCfg.intKeyFile,
		},
	}
}

func (common *CommonConfig) Flags() []cli.Flag {
	return append(common.certConfig.Flags(),
		&cli.StringFlag{
			Name:        "host",
			Value:       "localhost",
			Usage:       "Space-separated list of IP addresses to bind all servers to. Defaults to localhost if not specified.",
			Destination: &common.host,
		},
		&cli.IntFlag{
			Name:        "http_port",
			Value:       -1,
			Usage:       "Port number to listen on for HTTP requests, 0 to use any port, or -1 to disable.",
			Destination: &common.httpPort,
		},
		&cli.IntFlag{
			Name:        "https_port",
			Value:       -1,
			Usage:       "Port number to listen on for HTTPS requests, 0 to use any port, or -1 to disable.",
			Destination: &common.httpsPort,
		},
		&cli.IntFlag{
			Name:        "http_proxy_port",
			Value:       -1,
			Usage:       "Port number to listen on for HTTP proxy requests, 0 to use any port, or -1 to disable.",
			Destination: &common.httpProxyPort,
		},
		&cli.IntFlag{
			Name:        "https_to_http_port",
			Value:       -1,
			Usage:       "Port number to listen on for HTTP proxy requests over an HTTPS connection, 0 to use any port, or -1 to disable.",
			Destination: &common.httpSecureProxyPort,
		},
		&cli.StringFlag{
			Name:  "inject_scripts",
			Value: "deterministic",
			Usage: "A folder of JavaScript sources to inject in all pages. " +
				"By default a script is injected that eliminates sources of entropy " +
				"such as Date() and Math.random() deterministic. " +
				"CAUTION: Without deterministic.js, many pages will not replay.",
			Destination: &common.injectScriptsDir,
		},
		&cli.StringFlag{
			Name:        "out_dir",
			Usage:       "Output directory where log and miscellaneous files are stored",
			Destination: &common.outDir,
		},
	)
}

func (common *CommonConfig) CheckArgs(c *cli.Context) error {
	if common.outDir != "" {
		if err := os.MkdirAll(common.outDir, os.ModePerm); err != nil {
			log.Println(err)
			os.Exit(1)
		}

		file, err := os.Create(filepath.Join(common.outDir, "out.log"))

		if err != nil {
			log.Println(err)
			os.Exit(1)
		}

		os.Stdout = file
		os.Stderr = file

		c.App.Writer = file
		c.App.ErrWriter = file

		log.SetOutput(file)
	}

	if c.Args().Len() > 1 {
		return errors.New("too many args")
	}

	if c.Args().Len() != 1 {
		return errors.New("must specify archive_file")
	}

	if common.httpPort == -1 && common.httpsPort == -1 &&
		common.httpProxyPort == -1 && common.httpSecureProxyPort == -1 {
		return errors.New("must specify at least one port flag")
	}

	leafCertFiles := strings.Split(common.certConfig.leafCertFiles, ",")
	leafKeyFiles := strings.Split(common.certConfig.leafKeyFiles, ",")

	if len(leafCertFiles) != len(leafKeyFiles) {
		return fmt.Errorf("list of leaf cert files given should match list of leaf key files")
	}

	// Load leaf certs
	for i := 0; i < len(leafCertFiles); i++ {
		log.Printf("Loading leaf cert from %v\n", leafCertFiles[i])
		log.Printf("Loading leaf key from %v\n", leafKeyFiles[i])

		leaf_cert, err := tls.LoadX509KeyPair(leafCertFiles[i], leafKeyFiles[i])

		if err != nil {
			return fmt.Errorf("error opening leaf cert or leaf key files: %v", err)
		}

		common.leaf_certs = append(common.leaf_certs, leaf_cert)
	}

	// Load int certs
	log.Printf("Loading int cert from %v\n", common.certConfig.intCertFile)
	log.Printf("Loading int key from %v\n", common.certConfig.intKeyFile)

	var err error

	common.int_cert, err = tls.LoadX509KeyPair(common.certConfig.intCertFile, common.certConfig.intKeyFile)

	if err != nil {
		return fmt.Errorf("error opening int cert or int key files: %v", err)
	}

	return nil
}

func processInjectedScripts(injectScriptsDir string, timeSeedMs int64) ([]webreplay.ResponseTransformer, error) {
	transformers := make([]webreplay.ResponseTransformer, 0)

	if injectScriptsDir != "" {
		files, err := os.ReadDir(injectScriptsDir)

		if err != nil {
			return transformers, fmt.Errorf("error reading dir %s: %v", injectScriptsDir, err)
		}

		for _, file := range files {
			scriptFilename := file.Name()

			scriptFilepath := filepath.Join(
				injectScriptsDir,
				scriptFilename,
			)

			log.Printf("Loading script from %v\n", scriptFilepath)

			// Replace {{WPR_TIME_SEED_TIMESTAMP}} with the time seed.
			replacements := map[string]string{"{{WPR_TIME_SEED_TIMESTAMP}}": strconv.FormatInt(timeSeedMs, 10)}

			si, err := webreplay.NewScriptInjectorFromFile(
				scriptFilepath,
				scriptFilename,
				replacements,
			)

			if err != nil {
				return transformers, fmt.Errorf("error opening script %s: %v", scriptFilepath, err)
			}

			transformers = append(transformers, si)
		}
	}

	return transformers, nil
}

func (r *RecordCommand) Flags() []cli.Flag {
	return append(r.common.Flags(),
		&cli.StringFlag{
			Name:        "proxy_server_url",
			Value:       "",
			Usage:       "Proxy server to use when recording requests",
			Destination: &r.proxyServer,
		})
}

func (r *ReplayCommand) Flags() []cli.Flag {
	return append(r.common.Flags(),
		&cli.StringFlag{
			Name:        "rules_file",
			Value:       "",
			Usage:       "File containing rules to apply to responses during replay",
			Destination: &r.rulesFile,
		},
		&cli.BoolFlag{
			Name: "serve_response_in_chronological_sequence",
			Usage: "When an incoming request matches multiple recorded " +
				"responses, serve response in chronological sequence. " +
				"I.e. wpr responds to the first request with the first " +
				"recorded response, and the second request with the " +
				"second recorded response.",
			Destination: &r.serveResponseInChronologicalSequence,
		},
		&cli.BoolFlag{
			Name:        "disable_fuzzy_url_matching",
			Usage:       "When doing playback, require URLs to match exactly.",
			Destination: &r.disableFuzzyURLMatching,
		},
		&cli.BoolFlag{
			Name: "quiet_mode",
			Usage: "quiets the logging output by not logging the " +
				"ServeHTTP url call and responses",
			Destination: &r.quietMode,
		},
		&cli.StringFlag{
			Name:        "excludes_list",
			Value:       "",
			Usage:       "Space-separated list of websites to exclude",
			Destination: &r.excludesList,
		},
		&cli.BoolFlag{
			Name:        "disable_req_delay",
			Usage:       "When doing playback, do not include delays corresponding to request roundtrip durations",
			Destination: &r.disableReqDelay,
		},
		&cli.StringFlag{
			Name:        "theme",
			Usage:       "Archive theme to use (For example: light or dark)",
			Destination: &r.theme,
		})
}

func (r *RootCACommand) Flags() []cli.Flag {
	return append(r.certConfig.Flags(),
		&cli.StringFlag{
			Name:        "android_device_id",
			Value:       "",
			Usage:       "Device id of an android device. Only relevant for Android",
			Destination: &r.installer.AndroidDeviceId,
		},
		&cli.StringFlag{
			Name:        "adb_binary_path",
			Value:       "adb",
			Usage:       "Path to adb binary. Only relevant for Android",
			Destination: &r.installer.AdbBinaryPath,
		},
		// Most desktop machines Google engineers use come with certutil installed.
		// In the chromium lab, desktop bots do not have certutil. Instead, desktop bots
		// deploy certutil binaries to <chromium src>/third_party/nss/certutil.
		// To accommodate chromium bots, the following flag accepts a custom path to
		// certutil. Otherwise WPR assumes that certutil resides in the PATH.
		&cli.StringFlag{
			Name:        "certutil_path",
			Value:       "certutil",
			Usage:       "Path to Network Security Services (NSS)'s certutil tool.",
			Destination: &r.installer.CertUtilBinaryPath,
		})
}

func startServers(startTime time.Time, tlsconfig *tls.Config,
	httpHandler, httpsHandler http.Handler, common *CommonConfig, ma *webreplay.MultipleArchive) {
	type Server struct {
		Scheme string
		Host   string
		Port   int
		*http.Server
	}

	hosts := strings.Split(common.host, " ")
	servers := []*Server{}

	httpPortForProxy := make(chan int, len(hosts))
	httpsPortForProxy := make(chan int, len(hosts))

	if common.httpProxyPort > -1 {
		if common.httpPort == -1 {
			common.httpPort = 0
		}

		if common.httpsPort == -1 {
			common.httpsPort = 0
		}

		// Simultaneous HTTP proxy and HTTPS-to-HTTP proxy
		// are not supported
		common.httpSecureProxyPort = -1
	}

	for _, host := range hosts {
		if common.httpPort > -1 {
			servers = append(servers, &Server{
				Scheme: "http",
				Host:   host,
				Port:   common.httpPort,
				Server: &http.Server{
					Addr:    fmt.Sprintf("%v:%v", host, common.httpPort),
					Handler: httpHandler,
				},
			})
		}

		if common.httpsPort > -1 {
			servers = append(servers, &Server{
				Scheme: "https",
				Host:   host,
				Port:   common.httpsPort,
				Server: &http.Server{
					Addr:      fmt.Sprintf("%v:%v", host, common.httpsPort),
					Handler:   httpsHandler,
					TLSConfig: tlsconfig,
					ConnState: webreplay.ConnStateHook,
				},
			})
		}

		if common.httpSecureProxyPort > -1 {
			servers = append(servers, &Server{
				Scheme: "https",
				Host:   host,
				Port:   common.httpSecureProxyPort,
				Server: &http.Server{
					Addr:      fmt.Sprintf("%v:%v", host, common.httpSecureProxyPort),
					Handler:   httpHandler, // this server proxies HTTP requests over an HTTPS connection
					TLSConfig: nil,         // use the default since this is as a proxy, not a MITM server
				},
			})
		}
	}

	for _, s := range servers {
		s := s

		go func() {
			var ln net.Listener
			var err error

			switch s.Scheme {
			case "http":
				ln, err = webreplay.GetTCPKeepAliveListener(s.Host, s.Port, ma)

				if err != nil {
					break
				}

				httpPortForProxy <- ln.Addr().(*net.TCPAddr).Port

				logServeStarted(s.Scheme, ln)

				err = s.Serve(ln)
			case "https":
				ln, err = webreplay.GetTCPKeepAliveListener(s.Host, s.Port, ma)

				if err != nil {
					break
				}

				httpsPortForProxy <- ln.Addr().(*net.TCPAddr).Port

				logServeStarted(s.Scheme, ln)

				http2.ConfigureServer(s.Server, &http2.Server{})
				tlsListener := tls.NewListener(ln, s.TLSConfig)

				err = s.Serve(tlsListener)
			default:
				panic(fmt.Sprintf("unknown s.Scheme: %s", s.Scheme))
			}

			if err != nil {
				log.Printf("Failed to start server on %s://%s: %v", s.Scheme, s.Addr, err)
			}
		}()
	}

	if common.httpProxyPort > -1 {
		for _, host := range hosts {
			go func() {
				startProxyServer(host, common, <-httpPortForProxy, <-httpsPortForProxy)
			}()
		}
	}

	log.Printf("Started servers in %v", time.Now().Sub(startTime))

	select {}
}

type NilLogger struct{}

func (l NilLogger) Printf(format string, v ...interface{}) {}

func startProxyServer(host string, common *CommonConfig, httpPort int, httpsPort int) {
	proxy := goproxy.NewProxyHttpServer()

	proxy.Verbose = false
	proxy.Logger = NilLogger{}

	ln, err := webreplay.GetTCPKeepAliveListener(host, common.httpProxyPort, nil)

	if err != nil {
		log.Fatal(
			"Failed to listen on HTTP proxy %s:%s",
			host, common.httpProxyPort,
		)
	}

	logServeStarted("http[PROXY]", ln)

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// HTTP dialer
	proxy.Tr = http.DefaultTransport.(*http.Transport).Clone()
	proxy.Tr.DialContext =
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(
				ctx,
				network,
				net.JoinHostPort(
					host,
					strconv.Itoa(httpPort),
				),
			)
		}

	// HTTPS dialer
	proxy.ConnectDial =
		func(network string, addr string) (net.Conn, error) {
			return dialer.Dial(
				network,
				net.JoinHostPort(
					host,
					strconv.Itoa(httpsPort),
				),
			)
		}

	err = http.Serve(ln, proxy)

	if err != nil {
		log.Fatal("Failed to start HTTP proxy server")
	}
}

func logServeStarted(scheme string, ln net.Listener) {
	log.Printf("Starting server on %s://%s", scheme, ln.Addr().String())
}

func isDir(path string) (bool, error) {
	fileInfo, err := os.Stat(path)

	if err != nil {
		return filepath.Ext(path) == "", nil
	}

	return fileInfo.IsDir(), nil
}

func makeMultipleArchive() *webreplay.MultipleArchive {
	multipleArchive := new(webreplay.MultipleArchive)

	multipleArchive.Archives = make([]*webreplay.Archive, 0)
	multipleArchive.Transformers = make([][]webreplay.ResponseTransformer, 0)
	multipleArchive.Names = make([]string, 0)

	multipleArchive.InitIndex = -1
	multipleArchive.PrevIndex = -1

	return multipleArchive
}

func makeMultipleWritableArchive(isDir bool, dir string) *webreplay.MultipleWritableArchive {
	mwa := new(webreplay.MultipleWritableArchive)

	mwa.IsDir = isDir
	mwa.Dir = dir

	mwa.WritableArchives = make([]*webreplay.WritableArchive, 0)
	mwa.Names = make([]string, 0)

	return mwa
}

func (r *RecordCommand) Run(c *cli.Context) error {
	startTime := time.Now()

	pathArg := c.Args().First()
	isDir, err := isDir(pathArg)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error checking archive path: %v", err)
		os.Exit(1)
	}

	archiveFileName := pathArg
	mwa := makeMultipleWritableArchive(isDir, pathArg)

	if isDir {
		if err := os.MkdirAll(pathArg, os.ModePerm); err != nil {
			log.Println(err)
			os.Exit(1)
		}

		archiveFileName = filepath.Join(pathArg, "default.json.gz")
	}

	archive, err := webreplay.OpenWritableArchive(archiveFileName)

	if err != nil {
		fmt.Println(err)
		cli.ShowSubcommandHelp(c)
		os.Exit(1)
	}

	defer archive.Close()

	log.Printf("Opened archive %s", archiveFileName)

	// Install a SIGINT handler to close the archive before shutting down.
	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, os.Interrupt)
		<-sigchan

		log.Printf("Shutting down")

		if err := mwa.Close(); err != nil {
			log.Printf("Error flushing archive: %v", err)
		}

		os.Exit(0)
	}()

	timeSeedMs := time.Now().Unix() * 1000

	transformers, err := processInjectedScripts(r.common.injectScriptsDir, timeSeedMs)

	if err != nil {
		log.Printf("Error processing injected scripts: %v", err)
		os.Exit(1)
	}

	archive.DeterministicTimeSeedMs = timeSeedMs

	mwa.WritableArchives = append(mwa.WritableArchives, archive)
	mwa.Transformers = transformers
	mwa.Names = append(mwa.Names, "default")

	siteLog := webreplay.CreateSiteLog(r.common.outDir)

	var proxyServerURL *url.URL
	if r.proxyServer != "" {
		proxyServerURL, err = url.Parse(r.proxyServer)

		if err != nil {
			log.Println("error parsing proxy URL:", err)
			os.Exit(1)
		}

		log.Printf("Using proxy server %v", proxyServerURL)
	}

	httpHandler := webreplay.NewRecordingProxy(mwa, "http", siteLog, proxyServerURL)
	httpsHandler := webreplay.NewRecordingProxy(mwa, "https", siteLog, proxyServerURL)
	tlsconfig, err := webreplay.RecordTLSConfig(r.common.leaf_certs, r.common.int_cert, mwa)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating TLSConfig: %v", err)
		os.Exit(1)
	}

	startServers(startTime, tlsconfig, httpHandler, httpsHandler, &r.common, nil)

	return nil
}

func (r *ReplayCommand) Run(c *cli.Context) error {
	startTime := time.Now()

	var wg sync.WaitGroup
	var mu sync.Mutex

	pathArg := c.Args().First()
	isDir, err := isDir(pathArg)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error checking archive path: %v", err)
		os.Exit(1)
	}

	archivePaths := make([]string, 0)
	ma := makeMultipleArchive()

	if isDir {
		entries, err := os.ReadDir(pathArg)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading archive path: %v", err)
		}

		for _, e := range entries {
			if e.IsDir() && e.Name() == r.theme {
				themePath := filepath.Join(pathArg, e.Name())
				themeEntries, err := os.ReadDir(themePath)

				if err != nil {
					fmt.Fprintf(os.Stderr, "Error reading archive theme path: %v", err)
				}

				for _, te := range themeEntries {
					archivePaths = append(archivePaths, filepath.Join(themePath, te.Name()))
				}
			} else if !e.IsDir() {
				archivePaths = append(archivePaths, filepath.Join(pathArg, e.Name()))
			}
		}
	} else {
		archivePaths = append(archivePaths, pathArg)
	}

	for _, archiveFileName := range archivePaths {
		wg.Add(1)

		go func(archiveFileName string) {
			defer wg.Done()

			log.Printf("Loading archive file from %s\n", archiveFileName)

			t0 := time.Now()
			archive, err := webreplay.OpenArchive(archiveFileName)
			t1 := time.Now()

			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening archive file: %v", err)
				os.Exit(1)
			}

			log.Printf("Opened archive %s %dms", archiveFileName, t1.Sub(t0).Milliseconds())

			archive.ServeResponseInChronologicalSequence = r.serveResponseInChronologicalSequence
			archive.DisableFuzzyURLMatching = r.disableFuzzyURLMatching

			if archive.DisableFuzzyURLMatching {
				log.Printf("Disabling fuzzy URL matching.")
			}

			timeSeedMs := archive.DeterministicTimeSeedMs

			if timeSeedMs == 0 {
				// The time seed hasn't been set in the archive. Time seeds used to not be
				// stored in the archive, so this is expected to happen when loading old
				// archives. Just revert to the previous behavior: use the current time as
				// the seed.
				timeSeedMs = time.Now().Unix() * 1000
			}

			transformers, err := processInjectedScripts(r.common.injectScriptsDir, timeSeedMs)

			if err != nil {
				log.Printf("Error processing injected scripts: %v", err)
				os.Exit(1)
			}

			if r.rulesFile != "" {
				t, err := webreplay.NewRuleBasedTransformer(r.rulesFile)

				if err != nil {
					fmt.Fprintf(os.Stderr, "Error opening rules file %s: %v\n", r.rulesFile, err)
					os.Exit(1)
				}

				transformers = append(transformers, t)

				log.Printf("Loaded replay rules from %s", r.rulesFile)
			}

			baseName := strings.TrimSuffix(filepath.Base(archiveFileName), ".json.gz")

			mu.Lock()
			ma.Archives = append(ma.Archives, archive)
			ma.Transformers = append(ma.Transformers, transformers)
			ma.Names = append(ma.Names, baseName)

			if baseName == "init" {
				ma.InitIndex = int32(len(ma.Names) - 1)
			}
			mu.Unlock()
		}(archiveFileName)
	}

	wg.Wait()

	if r.excludesList != "" {
		log.Printf("Using excludes list \"%s\"", r.excludesList)
	}

	if r.disableReqDelay {
		log.Printf("Disabling request roundtrip delays")
	}

	siteLog := webreplay.CreateSiteLog(r.common.outDir)

	httpHandler := webreplay.NewReplayingProxy(
		ma, "http", r.quietMode, r.excludesList, r.disableReqDelay, siteLog,
	)

	httpsHandler := webreplay.NewReplayingProxy(
		ma, "https", r.quietMode, r.excludesList, r.disableReqDelay, siteLog,
	)

	tlsconfig, err := webreplay.ReplayTLSConfig(r.common.leaf_certs, r.common.int_cert, ma)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating TLSConfig: %v", err)
		os.Exit(1)
	}

	startServers(startTime, tlsconfig, httpHandler, httpsHandler, &r.common, ma)

	return nil
}

func (r *RootCACommand) Install(c *cli.Context) error {
	if err := r.installer.InstallRoot(
		r.certConfig.leafCertFiles, r.certConfig.leafKeyFiles); err != nil {
		fmt.Fprintf(os.Stderr, "Install root failed: %v", err)
		os.Exit(1)
	}
	return nil
}

func (r *RootCACommand) Remove(c *cli.Context) error {
	r.installer.RemoveRoot()
	return nil
}

func main() {
	progName := filepath.Base(os.Args[0])

	var record RecordCommand
	var replay ReplayCommand
	var installroot RootCACommand
	var removeroot RootCACommand

	record.cmd = cli.Command{
		Name:   "record",
		Usage:  "Record web pages to an archive",
		Flags:  record.Flags(),
		Before: record.common.CheckArgs,
		Action: record.Run,
	}

	replay.cmd = cli.Command{
		Name:   "replay",
		Usage:  "Replay a previously-recorded web page archive",
		Flags:  replay.Flags(),
		Before: replay.common.CheckArgs,
		Action: replay.Run,
	}

	installroot.cmd = cli.Command{
		Name:   "installroot",
		Usage:  "Install a test root CA",
		Flags:  installroot.Flags(),
		Action: installroot.Install,
	}

	removeroot.cmd = cli.Command{
		Name:   "removeroot",
		Usage:  "Remove a test root CA",
		Flags:  removeroot.Flags(),
		Action: removeroot.Remove,
	}

	app := cli.NewApp()
	app.Commands = []*cli.Command{&record.cmd, &replay.cmd, &installroot.cmd, &removeroot.cmd}
	app.Usage = "Web Replay"
	app.UsageText = fmt.Sprintf(longUsage, progName, progName)
	app.HideVersion = true
	app.Version = ""
	app.RunAndExitOnError()
}
