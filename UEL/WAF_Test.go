package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

type Statistics struct {
	TotalRequests      int
	BlockedRequests    int
	SuccessfulRequests int
	FailedRequests     int
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run Test-WAF.go <URL>")
		return
	}

	baseURL := os.Args[1]
	stats := &Statistics{}
	startTime := time.Now()

	csvFile, err := os.Create("results.csv")
	if err != nil {
		logError(fmt.Sprintf("Failed to create CSV file: %v\n", err))
		return
	}
	defer csvFile.Close()

	writer := csv.NewWriter(csvFile)
	defer writer.Flush()

	writer.Write([]string{"Status", "Payload", "HTTP Status", "Content Length"})

	processPayloadsFile("./All_Attacks.txt", baseURL, stats, writer)

	endTime := time.Now()

	printStatistics(stats, startTime, endTime)
}

func processPayloadsFile(filePath string, baseURL string, stats *Statistics, writer *csv.Writer) {
	file, err := os.Open(filePath)
	if err != nil {
		logError(fmt.Sprintf("Failed to open file %s: %v\n", filePath, err))
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		payload := scanner.Text()
		encodedPayload := encodePayload(payload)
		url := fmt.Sprintf("%s?payload=%s", baseURL, encodedPayload)
		sendRequest(payload, url, stats, writer)
	}

	if err := scanner.Err(); err != nil {
		logError(fmt.Sprintf("Error reading file %s: %v\n", filePath, err))
	}
}

func encodePayload(payload string) string {
	payload = strings.ReplaceAll(payload, " ", "%20")
	payload = strings.ReplaceAll(payload, "&", "%28")
	//	return url.QueryEscape(payload)
	return payload
}

func sendRequest(payload, url string, stats *Statistics, writer *csv.Writer) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logError(fmt.Sprintf("Failed to create request: %v\n", err))
		stats.FailedRequests++
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0")

	resp, err := client.Do(req)
	if err != nil {
		logError(fmt.Sprintf("Failed to send request to %s: %v\n", url, err))
		stats.FailedRequests++
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logError(fmt.Sprintf("Failed to read response body: %v\n", err))
		stats.FailedRequests++
		return
	}

	bodyString := string(bodyBytes)
	contentLength := len(bodyBytes)

	stats.TotalRequests++
	status := "Success"
	if strings.Contains(bodyString, "Web Page Blocked") {
		stats.BlockedRequests++
		status = "Blocked"
	} else {
		stats.SuccessfulRequests++
	}

	fmt.Println(" - STATUS: " + status + " | REQUEST SENT: " + url)
	writer.Write([]string{status, payload, fmt.Sprintf("%d", resp.StatusCode), fmt.Sprintf("%d", contentLength)})
	writer.Flush()
}

func printStatistics(stats *Statistics, startTime, endTime time.Time) {
	fmt.Printf("Total requests sent: %d\n", stats.TotalRequests)
	fmt.Printf("Blocked requests: %d\n", stats.BlockedRequests)
	fmt.Printf("Successful requests: %d\n", stats.SuccessfulRequests)
	fmt.Printf("Failed requests: %d\n", stats.FailedRequests)
	fmt.Printf("Execution time: %s\n", endTime.Sub(startTime))
}

func logError(message string) {
	f, err := os.OpenFile("errors.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open error log file: %v\n", err)
		return
	}
	defer f.Close()

	logger := bufio.NewWriter(f)
	message = strings.ReplaceAll(message, ",", `\,`)
	logger.WriteString(message + "\n")
	logger.Flush()
}
