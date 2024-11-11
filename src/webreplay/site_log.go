// Copyright (c) Microsoft Corporation.
// Licensed under the BSD-3-Clause license.

package webreplay

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

type SiteLog struct {
	outDir string
	table  map[string][]json.RawMessage
	mu     sync.Mutex
}

func CreateSiteLog(outDir string) *SiteLog {
	siteLog := new(SiteLog)
	siteLog.outDir = outDir
	siteLog.table = make(map[string][]json.RawMessage)

	return siteLog
}

func (siteLog *SiteLog) recordLog(req *http.Request) {
	siteLog.mu.Lock()
	defer siteLog.mu.Unlock()

	defer req.Body.Close()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Println(err)
		return
	}

	var data struct {
		From    string          `json:"from"`
		Content json.RawMessage `json:"content"`
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		log.Println(err)
		return
	}

	if data.From == "" {
		log.Println("Invalid from")
		return
	}

	if messages, ok := siteLog.table[data.From]; ok {
		siteLog.table[data.From] = append(messages, data.Content)
	} else {
		siteLog.table[data.From] = []json.RawMessage{data.Content}
	}
}

func (siteLog *SiteLog) saveLog() {
	siteLog.mu.Lock()
	defer siteLog.mu.Unlock()

	if _, err := os.Stat(siteLog.outDir); err != nil {
		log.Println("Output directory does not exist")
		return
	}

	for from, messages := range siteLog.table {
		if len(messages) == 0 {
			continue
		}

		file, err := os.Create(
			filepath.Join(siteLog.outDir, fmt.Sprintf("%s.json", from)),
		)
		if err != nil {
			log.Println(err)
			continue
		}
		defer file.Close()

		pMessages, err := json.MarshalIndent(messages, "", "    ")
		if err != nil {
			log.Println(err)
			continue
		}

		_, err = file.Write(append(pMessages, '\n'))
		if err != nil {
			log.Println(err)
		}
	}

	siteLog.table = make(map[string][]json.RawMessage)
}
