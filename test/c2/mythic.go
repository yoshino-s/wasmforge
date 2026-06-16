//go:build mythic

package c2

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// MythicClient wraps Mythic's Hasura GraphQL API for test automation.
type MythicClient struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

// NewMythicClient authenticates to Mythic and returns a client.
func NewMythicClient(apiURL, username, passwordEnv string) (*MythicClient, error) {
	password := os.Getenv(passwordEnv)
	if password == "" {
		return nil, fmt.Errorf("env var %s not set", passwordEnv)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Authenticate to get JWT.
	authURL := strings.TrimSuffix(apiURL, "/graphql") + "/auth"
	authBody, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})

	resp, err := client.Post(authURL, "application/json", bytes.NewReader(authBody))
	if err != nil {
		return nil, fmt.Errorf("authenticating: %w", err)
	}
	defer resp.Body.Close()

	var authResp struct {
		AccessToken string `json:"access_token"`
		Status      string `json:"status"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &authResp); err != nil {
		return nil, fmt.Errorf("parsing auth response: %w (body: %s)", err, body)
	}
	if authResp.AccessToken == "" {
		return nil, fmt.Errorf("auth failed: %s", body)
	}

	return &MythicClient{
		baseURL:    apiURL,
		httpClient: client,
		token:      authResp.AccessToken,
	}, nil
}

// graphqlQuery executes a GraphQL query and returns the parsed response.
func (m *MythicClient) graphqlQuery(query string, variables map[string]any) (map[string]any, error) {
	reqBody, _ := json.Marshal(map[string]any{
		"query":     query,
		"variables": variables,
	})

	graphqlURL := m.baseURL
	if !strings.HasSuffix(graphqlURL, "/graphql") {
		graphqlURL += "/graphql"
	}

	req, err := http.NewRequest("POST", graphqlURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.token)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing graphql response: %w (body: %s)", err, body)
	}

	if errors, ok := result["errors"]; ok {
		return nil, fmt.Errorf("graphql errors: %v", errors)
	}

	data, ok := result["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected response structure: %s", body)
	}
	return data, nil
}

// WaitForCallback polls for a callback matching the given payload UUID.
// If payloadUUID is empty, matches the most recently created callback.
func (m *MythicClient) WaitForCallback(payloadUUID string, timeout time.Duration) (*Beacon, error) {
	deadline := time.Now().Add(timeout)

	// Use filtered query when UUID provided, unfiltered (latest) otherwise.
	var query string
	var variables map[string]any

	if payloadUUID != "" {
		query = `query GetCallbacks($uuid: String!) {
			callback(where: {registered_payload: {uuid: {_eq: $uuid}}}, order_by: {id: desc}, limit: 1) {
				id
				host
				user
				pid
				os
			}
		}`
		variables = map[string]any{"uuid": payloadUUID}
	} else {
		query = `query GetLatestCallback {
			callback(order_by: {id: desc}, limit: 1) {
				id
				host
				user
				pid
				os
			}
		}`
		variables = nil
	}

	for time.Now().Before(deadline) {
		data, err := m.graphqlQuery(query, variables)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		callbacks, ok := data["callback"].([]any)
		if ok && len(callbacks) > 0 {
			cb := callbacks[0].(map[string]any)
			return &Beacon{
				ID:       fmt.Sprintf("%.0f", cb["id"]),
				Hostname: fmt.Sprintf("%v", cb["host"]),
				Username: fmt.Sprintf("%v", cb["user"]),
				OS:       fmt.Sprintf("%v", cb["os"]),
				PID:      int(cb["pid"].(float64)),
			}, nil
		}

		time.Sleep(5 * time.Second)
	}

	return nil, fmt.Errorf("no callback for payload %s within %v", payloadUUID, timeout)
}

// CreateTask issues a command to a callback and returns the task ID.
func (m *MythicClient) CreateTask(callbackID int, command, params string) (int, error) {
	query := `mutation CreateTask($callback_id: Int!, $command: String!, $params: String!) {
		createTask(callback_id: $callback_id, command: $command, params: $params) {
			id
			status
			error
		}
	}`

	data, err := m.graphqlQuery(query, map[string]any{
		"callback_id": callbackID,
		"command":     command,
		"params":      params,
	})
	if err != nil {
		return 0, err
	}

	task, ok := data["createTask"].(map[string]any)
	if !ok {
		return 0, fmt.Errorf("unexpected createTask response: %v", data)
	}

	if errStr, ok := task["error"].(string); ok && errStr != "" {
		return 0, fmt.Errorf("task creation error: %s", errStr)
	}

	taskID := int(task["id"].(float64))
	return taskID, nil
}

// WaitForTaskResult polls until a task completes and returns its output.
func (m *MythicClient) WaitForTaskResult(taskID int, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)

	query := `query GetTask($id: Int!) {
		task_by_pk(id: $id) {
			status
			completed
			responses {
				response
			}
		}
	}`

	for time.Now().Before(deadline) {
		data, err := m.graphqlQuery(query, map[string]any{"id": taskID})
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		task, ok := data["task_by_pk"].(map[string]any)
		if !ok {
			time.Sleep(2 * time.Second)
			continue
		}

		completed, _ := task["completed"].(bool)
		if !completed {
			time.Sleep(2 * time.Second)
			continue
		}

		responses, ok := task["responses"].([]any)
		if !ok || len(responses) == 0 {
			return "", nil
		}

		var output strings.Builder
		for _, r := range responses {
			resp := r.(map[string]any)
			if s, ok := resp["response"].(string); ok {
				output.WriteString(s)
				output.WriteString("\n")
			}
		}
		return strings.TrimSpace(output.String()), nil
	}

	return "", fmt.Errorf("task %d did not complete within %v", taskID, timeout)
}
