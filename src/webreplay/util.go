// Copyright (c) Microsoft Corporation.
// Licensed under the BSD-3-Clause license.

package webreplay

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var commonDeterministicExclude = []string{
	`(.+[.])*nytimes\.com`,
	`(.+[.])*amazon\.com`,
	`(.+[.])*bbc\.com`,
	domainToRegexp("google.com"),
}

var deterministicHostMap = map[string][]string{
	"common":  {".*"},
	"outlook": {".*outlook.*"},
	"youtube": {".*youtube.*"},
	"nytimes": {".*nytimes.*"},
	"amazon":  {`.*amazon\.com`},
	"bbc":     {`.*bbc\.com`},
	"reddit":  {`.*reddit\.com`},
	"google":  {domainToRegexp("google.com")},
}

var websiteHostMap = map[string]string{
	"reddit":    "reddit.com",
	"instagram": "instagram.com",
	"amazon":    "amazon.com",
	"google":    "google.com",
	"youtube":   "youtube.com",
	"wikipedia": "wikipedia.org",
	"nytimes":   "nytimes.com",
	"bing":      "bing.com",
	"bbc":       "bbc.com",
	"edge":      "edge.microsoft.com",
	"ntp":       "ntp.msn.com",
}

func createRe(reList []string) string {
	var reListMapped []string

	if len(reList) > 1 {
		for _, re := range reList {
			reListMapped = append(
				reListMapped,
				"("+re+")",
			)
		}
	} else if len(reList) > 0 {
		return reList[0]
	} else {
		return "[]"
	}

	return strings.Join(reListMapped, "|")
}

func domainToRegexp(domain string) string {
	return fmt.Sprintf(
		`^(.+[.])*%s$`,
		regexp.QuoteMeta(domain),
	)
}

func domainToRegexpExact(domain string) string {
	return fmt.Sprintf(
		`^%s$`,
		regexp.QuoteMeta(domain),
	)
}

func IsSubdomain(root string, sub string) bool {
	matched, err := regexp.Match(
		domainToRegexp(root),
		[]byte(sub),
	)

	return err == nil && matched
}

func ExcludeRequest(req *http.Request, websites []string) bool {
	for _, website := range websites {
		domain := website

		if !strings.Contains(website, ".") {
			var ok bool

			domain, ok = websiteHostMap[strings.ToLower(website)]

			if !ok {
				continue
			}
		}

		pattern := domainToRegexp(domain)

		matched, err := regexp.Match(pattern, []byte(req.URL.Host))

		if err == nil && matched {
			return true
		}

		if originHeader, err := url.Parse(req.Header.Get("Origin")); err == nil {
			matched, err = regexp.Match(pattern, []byte(originHeader.Host))

			if err == nil && matched {
				return true
			}
		}

		if refererHeader, err := url.Parse(req.Header.Get("Referer")); err == nil {
			matched, err = regexp.Match(pattern, []byte(refererHeader.Host))

			if err == nil && matched {
				return true
			}
		}
	}

	return false
}

func ShouldIncludeTransformation(req *http.Request, filename string) bool {
	file_prefix := strings.Split(filename, "_")[0]

	if file_prefix == "common" {
		matched, err := regexp.Match(
			createRe(commonDeterministicExclude),
			[]byte(req.URL.Host),
		)

		if err != nil || matched {
			return false
		}
	}

	matched, err := regexp.Match(
		createRe(deterministicHostMap[file_prefix]),
		[]byte(req.URL.Host),
	)

	if err == nil && matched {
		return true
	}

	return false
}

func Is2xxOr3xx(resp *http.Response) bool {
	return resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusBadRequest
}
