// writer.go - File Writer
// Copyright (c) 2015 Kamilla Productions Uninc. Author Joonas Greis  All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

package brainwallet

import (
	"bufio"
	"log"
	"os"
	"sync"
)

// File Writer
func Writer(file string, output chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	outputFile, err := os.Create(file) // Create a file
	if err != nil {
		log.Fatal(err)
		return
	}
	// outputFile, err := os.OpenFile(file, os.O_WRONLY|os.O_APPEND, 0644) // Append file
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	defer outputFile.Close()

	writer := bufio.NewWriter(outputFile)

	for line := range output {

		writer.WriteString(line + "\n") // Write line to file
		writer.Flush()                  // Flush writer
	}
}
