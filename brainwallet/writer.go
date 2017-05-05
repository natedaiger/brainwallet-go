// writer.go - File Writer
// Copyright (c) 2015 Kamilla Productions Uninc. Author Joonas Greis  All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

package brainwallet

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sync"
)

// File Writer
func Writer(file string, output chan string, done chan int, wg *sync.WaitGroup) {
	defer wg.Done()

	fmt.Printf("WRITER STARTED\n")
waitfordone:
	for {
		select {
		case line := <-output: // received line from output channel
			fmt.Printf("Writing line:\n%s\n", line)

			outputFile, err := os.OpenFile(file, os.O_WRONLY|os.O_APPEND, 0644) // Append file
			if err != nil {
				log.Println(err)
				return
			}
			writer := bufio.NewWriter(outputFile)

			outputFile.WriteString(line + "\n") // Write line to file
			writer.Flush()                      // Flush writer
			outputFile.Close()

		case <-done: // Everything is done. Shutdown.

			fmt.Println("DONE WRITING.")
			break waitfordone
		}
	}
}

// File Creator
func CreateFile(file string) (err error) {
	outputFile, err := os.Create(file) // Create a file
	if err != nil {
		log.Fatal(err)
		return
	}
	defer outputFile.Close()
	return
}
