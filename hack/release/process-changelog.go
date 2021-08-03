// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Run this script with "go run process-changelog.go <PATH to CHANGELOG> > <PATH to new CHANGELOG>".
// The script will:
//  * Add links to PRs, by replacing all instances of [#<NUM>] with [#<NUM>](<link to PR NUM>)
//  * Add links to the Github profiles of PR authors. It will look for instances of [@<AUTHOR>] in
//    the CHANGELOG and generate the appropriate Markdown links at the end of the file.

package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	repo          = "https://github.com/antrea-io/antrea"
	authorBaseURL = "https://github.com"
)

var (
	pullBaseURL = fmt.Sprintf("%s/pull", repo)
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("This script expects exactly one argument, the path to the CHANGELOG file")
	}
	filePath := os.Args[1]
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	// Add links to all PRs: [#XXXX] -> [#XXXX](<link>)
	// Gather all author names: [@<author>]
	scanner := bufio.NewScanner(file)
	prRef := regexp.MustCompile(`\[#([0-9]+)\]([^(])`)
	authorRef := regexp.MustCompile(`\[@([a-zA-Z0-9-]+)\][^(]`)
	allAuthors := make(map[string]bool)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] != '-' {
			out.WriteString(line)
			out.WriteString("\n")
			continue
		}
		line = prRef.ReplaceAllString(line, fmt.Sprintf("[#$1](%s/$1)$2", pullBaseURL))
		matches := authorRef.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			allAuthors[match[1]] = true
		}
		out.WriteString(line)
		out.WriteString("\n")
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	out.Flush()
	log.Printf("Checking Github accounts, this could take a while...")

	numAuthors := len(allAuthors)
	sortedAuthors := make([]string, 0, numAuthors)
	for author := range allAuthors {
		sortedAuthors = append(sortedAuthors, author)
	}
	sort.Slice(sortedAuthors, func(i, j int) bool { return strings.ToLower(sortedAuthors[i]) < strings.ToLower(sortedAuthors[j]) })
	timeout := time.Duration(3 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}
	out.WriteString("\n")
	for _, author := range sortedAuthors {
		log.Printf("Checking %s", author)
		url := fmt.Sprintf("%s/%s", authorBaseURL, author)
		if _, err := client.Head(url); err != nil {
			log.Printf("FAILURE: %v", err)
		} else {
			log.Printf("SUCCESS")
		}
		out.WriteString(fmt.Sprintf("[@%s]: %s\n", author, url))
	}
}
