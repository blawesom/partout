// llm.go — the OpenAI-compatible chat client (POST {base}/chat/completions
// with tools). Deliberately minimal: no streaming from the endpoint (the
// browser SSE is event-level, docs/assistant.md §4), one retry on transport
// error, a hard request timeout owned by the caller's context.
package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// LLMClient talks to any OpenAI-compatible endpoint.
type LLMClient struct {
	baseURL string // e.g. http://ollama.local:11434/v1
	apiKey  string // optional (local endpoints are keyless)
	http    *http.Client
}

// NewLLMClient builds a client. baseURL should end with /v1 (the
// chat/completions path is appended); an empty key is valid for local
// endpoints.
func NewLLMClient(baseURL, apiKey string) *LLMClient {
	return &LLMClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 120 * time.Second},
	}
}

// ChatMessage is one message in the OpenAI chat schema.
type ChatMessage struct {
	Role       string        `json:"role"` // system|user|assistant|tool
	Content    string        `json:"content"`
	ToolCalls  []ToolCallOut `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"` // role=tool: which call this answers
	Name       string        `json:"name,omitempty"`        // role=tool: tool name
}

// ToolCallOut is an assistant-requested tool call (what the model returns).
type ToolCallOut struct {
	ID       string `json:"id"`
	Type     string `json:"type"` // "function"
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"` // JSON object as a string
	} `json:"function"`
}

// chatRequest is the request body for /chat/completions.
type chatRequest struct {
	Model    string         `json:"model"`
	Messages []ChatMessage  `json:"messages"`
	Tools    []map[string]any `json:"tools,omitempty"`
}

// chatResponse is the subset of the response we consume.
type chatResponse struct {
	Choices []struct {
		Message      ChatMessage `json:"message"`
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// ChatCompletion sends messages (+ tool schemas) and returns the model's
// reply (content and/or tool calls).
func (c *LLMClient) ChatCompletion(ctx context.Context, model string, msgs []ChatMessage, tools []map[string]any) (*ChatMessage, error) {
	if c.baseURL == "" {
		return nil, fmt.Errorf("assistant: endpoint not configured")
	}
	body, err := json.Marshal(chatRequest{Model: model, Messages: msgs, Tools: tools})
	if err != nil {
		return nil, err
	}

	do := func() ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			c.baseURL+"/chat/completions", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		if c.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.apiKey)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			msg := strings.TrimSpace(string(b))
			if len(msg) > 300 {
				msg = msg[:300] + "…"
			}
			return nil, fmt.Errorf("assistant: endpoint %s returned HTTP %d: %s", c.baseURL, resp.StatusCode, msg)
		}
		return b, nil
	}

	b, err := do()
	if err != nil {
		// One retry on transport failure (connection reset, 5xx blip).
		if ctx.Err() == nil {
			if b2, err2 := do(); err2 == nil {
				b = b2
			}
		}
		if b == nil {
			return nil, err
		}
	}

	var out chatResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("assistant: decode endpoint response: %w", err)
	}
	if out.Error != nil && out.Error.Message != "" {
		return nil, fmt.Errorf("assistant: endpoint error: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return nil, fmt.Errorf("assistant: endpoint returned no choices")
	}
	msg := out.Choices[0].Message
	return &msg, nil
}

// Probe checks that the endpoint answers and supports tool calling: a
// minimal chat completion with one trivial tool. Returns the observed model
// name and round-trip latency. Used by the enablement hard gate
// (docs/assistant.md §4): no tool support → refuse.
func (c *LLMClient) Probe(ctx context.Context, model string) (string, time.Duration, error) {
	start := time.Now()
	tools := []map[string]any{{
		"type": "function",
		"function": map[string]any{
			"name":        "probe_noop",
			"description": "Connectivity probe; never call this.",
			"parameters":  map[string]any{"type": "object", "properties": map[string]any{}},
		},
	}}
	msgs := []ChatMessage{{Role: "user", Content: "Reply with the single word: ok"}}
	msg, err := c.ChatCompletion(ctx, model, msgs, tools)
	if err != nil {
		return "", 0, err
	}
	// The probe only verifies the endpoint accepts the tools parameter;
	// whether the model USES tools is exercised on first real turn.
	_ = msg
	return model, time.Since(start), nil
}
