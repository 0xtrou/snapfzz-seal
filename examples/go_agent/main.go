package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type ChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	MaxTokens   int       `json:"max_tokens"`
	Temperature float64   `json:"temperature"`
	Stream      bool      `json:"stream"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
}

var (
	apiKey    = os.Getenv("SNAPFZZ_SEAL_API_KEY")
	apiBase   = getEnv("SNAPFZZ_SEAL_API_BASE", "https://llm.solo.engineer/v1")
	model     = getEnv("SNAPFZZ_SEAL_MODEL", "bcp/qwen3.6-plus")
	maxTokens = 2048
	temp      = 0.7
)

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func callLLM(prompt string) (string, error) {
	if apiKey == "" {
		return "", fmt.Errorf("SNAPFZZ_SEAL_API_KEY not set")
	}

	reqBody := ChatRequest{
		Model: model,
		Messages: []Message{
			{Role: "user", Content: prompt},
		},
		MaxTokens:   maxTokens,
		Temperature: temp,
		Stream:      true,
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", apiBase+"/chat/completions", strings.NewReader(string(jsonBody)))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var contentParts []string
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "data: ") && line != "data: [DONE]" {
			var chunk ChatResponse
			if err := json.Unmarshal([]byte(line[6:]), &chunk); err == nil {
				if len(chunk.Choices) > 0 {
					if chunk.Choices[0].Delta.Content != "" {
						contentParts = append(contentParts, chunk.Choices[0].Delta.Content)
					}
				}
			}
		}
	}

	return strings.Join(contentParts, ""), nil
}

func main() {
	prompt := os.Getenv("AGENT_PROMPT")
	if prompt == "" {
		prompt = "Hello! Introduce yourself in one sentence."
	}

	response, err := callLLM(prompt)
	if err != nil {
		response = fmt.Sprintf("Error: %v", err)
	}

	result := map[string]string{
		"prompt":   prompt,
		"response": response,
		"model":    model,
	}

	output, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(output))
}
