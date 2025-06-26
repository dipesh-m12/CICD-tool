// main.go
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json" // Use JSON for config
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// --- Configuration Structs ---

// Webhook represents a single webhook configuration.
type Webhook struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	URLPath string   `json:"url_path"` // Fixed to webhookBaseURL
	Script  string   `json:"script"`
	Emails  []string `json:"emails"`
}

// EmailConfig holds the settings for sending emails.
type EmailConfig struct {
	SenderEmail string `json:"sender_email"`
	AppPassword string `json:"app_password"`
	SMTPServer  string `json:"smtp_server"`
	SMTPPort    int    `json:"smtp_port"`
}

// Configuration represents the entire application configuration.
type Configuration struct {
	Webhooks []Webhook   `json:"webhooks"`
	Email    EmailConfig `json:"email"`
}

// --- Global Constants and Variables ---
const AppVersion = "1.1.0" // Set by developer
const configFileName = "config.json"
const webhookBaseURL = "/webhook"
const statusURL = "/status"
const defaultListenPort = 52606 // Fixed default port
const logDirectoryName = "logs"
const mainLogFileName = "cicd.log" // New: Name for the main application log

var (
	configPath    string
	logPath       string // Path to the logs directory
	mainLogFilePath string // New: Path to the main application log file
	configOnce    sync.Once
	currentConfig *Configuration
	server        *http.Server
	doneCh        = make(chan struct{}) // Channel to signal server shutdown completion
	serverPort    int                   // Store the port the server is running on
)

// --- Configuration Management Functions ---

// initConfig ensures the config and log directories exist and determines file paths.
func initConfig() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Warning: Could not determine user home directory: %v. Using current directory for config.\n", err)
		homeDir = "."
	}

	configDir := filepath.Join(homeDir, ".cicd-webhook")
	configPath = filepath.Join(configDir, configFileName)
	logPath = filepath.Join(configDir, logDirectoryName)     // Set webhook-specific log directory path
	mainLogFilePath = filepath.Join(configDir, mainLogFileName) // Set main application log file path

	if err := os.MkdirAll(configDir, 0700); err != nil {
		fmt.Printf("Warning: Could not create config directory %s: %v. Errors might occur.\n", configDir, err)
	}
	if err := os.MkdirAll(logPath, 0700); err != nil {
		fmt.Printf("Warning: Could not create webhook log directory %s: %v. Errors might occur.\n", logPath, err)
	}
}

// loadConfig loads the application configuration from the config file.
// It uses a singleton pattern to load the config only once.
func loadConfig() *Configuration {
	configOnce.Do(func() {
		currentConfig = &Configuration{}

		data, err := os.ReadFile(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("Configuration file not found at %s. Creating a new one.\n", configPath)
				currentConfig.Email = EmailConfig{
					SMTPServer: "smtp.example.com", // Placeholder
					SMTPPort:   587,
				}
				if err := saveConfig(currentConfig); err != nil {
					fmt.Printf("Failed to create initial config file: %v\n", err)
				}
				return
			}
			fmt.Printf("Error reading config file %s: %v. Using default empty configuration.\n", configPath, err)
			return
		}

		if err := json.Unmarshal(data, currentConfig); err != nil {
			fmt.Printf("Error unmarshaling config file %s: %v. Using default empty configuration.\n", configPath, err)
		}
	})
	return currentConfig
}

// saveConfig saves the current application configuration to the config file.
func saveConfig(cfg *Configuration) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", configPath, err)
	}
	return nil
}

// getWebhookLogFilePath returns the full path for a webhook's log file.
func getWebhookLogFilePath(webhookID string) string {
	return filepath.Join(logPath, fmt.Sprintf("webhook_%s.log", webhookID))
}

// --- Email Sending Function ---

// sendEmail sends an email notification.
func sendEmail(cfg EmailConfig, to []string, subject, body string) error {
	if cfg.SenderEmail == "" || cfg.AppPassword == "" || cfg.SMTPServer == "" || cfg.SMTPPort == 0 {
		return fmt.Errorf("email configuration is incomplete. Please configure it using 'cicd config email'")
	}

	msg := []byte("To: " + strings.Join(to, ",") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body + "\r\n")

	auth := smtp.PlainAuth("", cfg.SenderEmail, cfg.AppPassword, cfg.SMTPServer)

	addr := cfg.SMTPServer + ":" + strconv.Itoa(cfg.SMTPPort)
	err := smtp.SendMail(addr, auth, cfg.SenderEmail, to, msg)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// --- Server Functions ---

// startServer contains the core logic for starting the HTTP server.
func startServer(port int, conf *Configuration) {
	mux := http.NewServeMux()

	// Register the generic webhook handler
	mux.HandleFunc(webhookBaseURL, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed. Use POST for webhooks.", http.StatusMethodNotAllowed)
			return
		}

		webhookID := r.URL.Query().Get("id")
		if webhookID == "" {
			http.Error(w, "Webhook ID not provided in URL parameters (e.g., /webhook?id=YOUR_WEBHOOK_ID)", http.StatusBadRequest)
			return
		}

		var foundWebhook *Webhook
		for i, wh := range conf.Webhooks {
			if wh.ID == webhookID {
				foundWebhook = &conf.Webhooks[i]
				break
			}
		}

		if foundWebhook == nil {
			http.Error(w, fmt.Sprintf("Webhook with ID '%s' not found.", webhookID), http.StatusNotFound)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading request body for webhook '%s': %v\n", foundWebhook.Name, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		log.Printf("Webhook '%s' (ID: %s) triggered from %s with body: %s\n",
			foundWebhook.Name, foundWebhook.ID, r.RemoteAddr, string(body))

		envVars := os.Environ()
		paramsMap := r.URL.Query()
		paramDisplay := ""
		for key, values := range paramsMap {
			envKey := strings.ToUpper(key)
			envValue := strings.Join(values, ",")
			envVars = append(envVars, fmt.Sprintf("%s=%s", envKey, envValue))
			paramDisplay += fmt.Sprintf("%s=%s ", envKey, envValue)
		}
		paramDisplay = strings.TrimSpace(paramDisplay)

		// Execute script in a goroutine
		go func(wh Webhook, scriptEnv []string, requestBody string, remoteAddr string, paramDisplay string) {
			logFilePath := getWebhookLogFilePath(wh.ID)
			logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Printf("Error opening webhook log file for '%s': %v\n", wh.Name, err)
				// Proceed without logging to file if there's an error
			}
			defer func() {
				if logFile != nil {
					logFile.Close()
				}
			}()

			// Log execution start to the webhook-specific log file
			logMessage := fmt.Sprintf("\n--- Webhook Triggered: %s (%s) at %s ---\n", wh.Name, wh.ID, time.Now().Format(time.RFC3339))
			logMessage += fmt.Sprintf("Remote Address: %s\n", remoteAddr)
			logMessage += fmt.Sprintf("Request Body: %s\n", requestBody)
			logMessage += fmt.Sprintf("Script Parameters (Environment Vars): %s\n", paramDisplay)
			logMessage += "--- Script Output ---\n"
			if logFile != nil {
				logFile.WriteString(logMessage)
			}
			log.Printf("Executing script for webhook '%s'. Parameters available as environment variables: %s\n", wh.Name, paramDisplay)

			shell := "bash"
			shellArg := "-c"
			if runtime.GOOS == "windows" {
				shell = "cmd.exe"
				shellArg = "/C"
			}

			execCmd := exec.Command(shell, shellArg, wh.Script)
			execCmd.Env = scriptEnv

			// Use a buffer to capture output for email, and tee it to the log file
			var scriptOutputBuffer bytes.Buffer
			multiWriter := io.MultiWriter(&scriptOutputBuffer) // Start with buffer
			if logFile != nil {
				multiWriter = io.MultiWriter(&scriptOutputBuffer, logFile) // Add log file if available
			}

			execCmd.Stdout = multiWriter
			execCmd.Stderr = multiWriter

			status := "SUCCESS"
			errorMessage := ""

			err = execCmd.Run() // Use Run() instead of CombinedOutput() when setting Stdout/Stderr
			scriptOutput := scriptOutputBuffer.String()

			if err != nil {
				status = "FAILED"
				errorMessage = fmt.Sprintf("Error: %v", err)
				log.Printf("Script execution for '%s' FAILED: %v\nOutput:\n%s\n", wh.Name, err, scriptOutput)
			} else {
				log.Printf("Script execution for '%s' SUCCESS.\nOutput:\n%s\n", wh.Name, scriptOutput)
			}

			// Add a separator and status to the log file after execution
			if logFile != nil {
				logFile.WriteString(fmt.Sprintf("\n--- Script Finished: %s ---\n", status))
				if errorMessage != "" {
					logFile.WriteString(fmt.Sprintf("Error Details: %s\n", errorMessage))
				}
				logFile.WriteString(strings.Repeat("=", 60) + "\n\n")
			}

			if len(wh.Emails) > 0 {
				emailSubject := fmt.Sprintf("Webhook Triggered: %s - %s", wh.Name, status)
				emailBody := fmt.Sprintf("Webhook '%s' (ID: %s) was triggered.\n\n"+
					"Status: %s\n"+
					"Timestamp: %s\n"+
					"Remote Address: %s\n"+
					"Request Body:\n%s\n\n"+
					"Script Parameters (Environment Vars):\n%s\n\n"+
					"Script Output:\n%s\n\n"+
					"%s",
					wh.Name, wh.ID, status, time.Now().Format(time.RFC3339), remoteAddr,
					requestBody, paramDisplay, scriptOutput, errorMessage)

				if err := sendEmail(conf.Email, wh.Emails, emailSubject, emailBody); err != nil {
					log.Printf("Error sending email for webhook '%s': %v\n", wh.Name, err)
				} else {
					log.Printf("Email notification sent for webhook '%s' successfully.\n", wh.Name)
				}
			}
		}(*foundWebhook, envVars, string(body), r.RemoteAddr, paramDisplay) // Pass request details

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Webhook received and script execution initiated.")
	})

	// Add a GET /status endpoint
	mux.HandleFunc(statusURL, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed. Use GET for status check.", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Webhook server is running and healthy!")
	})

	publicIP, err := getPublicIP()
	if err != nil {
		log.Printf("Warning: Could not determine public IP: %v. Displaying local address.\n", err)
	}

	listenAddr := fmt.Sprintf(":%d", port)
	server = &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}
	serverPort = port // Store the port

	if publicIP != "" {
		fmt.Printf("Webhook server is accessible at: http://%s:%d%s\n", publicIP, port, webhookBaseURL)
		fmt.Printf("Server status check: http://%s:%d%s\n", publicIP, port, statusURL)
	} else {
		fmt.Printf("Webhook server is accessible at: http://localhost:%d%s\n", port, webhookBaseURL)
		fmt.Printf("Server status check: http://localhost:%d%s\n", port, statusURL)
	}

	fmt.Println("\n--- IMPORTANT: To run this server in the background: ---")
	fmt.Println("  On Linux/macOS: nohup ./cicd start & (Output goes to nohup.out and/or cicd.log)")
	fmt.Println("  On Windows (using cmd.exe): start /B cicd.exe start")
	fmt.Println("--------------------------------------------------")

	log.Printf("Server listening on %s\n", listenAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
	close(doneCh)
}

// stopServer attempts to gracefully shut down the HTTP server.
func stopServer() {
	if server != nil {
		log.Println("Attempting to gracefully shut down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown failed: %v", err)
		} else {
			log.Println("Server gracefully stopped.")
		}
		select {
		case <-doneCh:
		case <-time.After(6 * time.Second):
			log.Println("Timed out waiting for server goroutine to signal completion. It might still be winding down.")
		}
		server = nil
	} else {
		fmt.Println("No server instance found running in this process.")
		fmt.Println("\n--- To stop a background server process manually: ---")
		fmt.Println("  1. Find the Process ID (PID):")
		fmt.Println("     On Linux/macOS: ps aux | grep cicd | grep -v grep")
		fmt.Println("     On Windows: tasklist | findstr /I \"cicd.exe\"")
		fmt.Println("  2. Terminate the process using its PID:")
		fmt.Println("     On Linux/macOS: kill <PID>")
		fmt.Println("     On Windows: taskkill /F /PID <PID>")
		fmt.Println("--------------------------------------------------")
	}
}

// findFreePort finds an available port on the system.
func findFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, fmt.Errorf("failed to resolve TCP address: %w", err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("failed to listen on TCP address: %w", err)
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port, nil
}

// getPublicIP fetches the public IP address using an external service.
func getPublicIP() (string, error) {
	resp, err := http.Get("http://icanhazip.com")
	if err != nil {
		return "", fmt.Errorf("failed to query external IP service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("external IP service returned non-OK status: %d", resp.StatusCode)
	}

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response from external IP service: %w", err)
	}

	return strings.TrimSpace(string(ip)), nil
}

// --- Helper for Partial ID Matching ---

// findWebhookByPartialID finds webhooks whose ID or Name contains the given partialID.
// It returns a slice of pointers to matching webhooks.
func findWebhookByPartialID(partialID string, conf *Configuration) []*Webhook {
	matches := []*Webhook{}
	lowerPartialID := strings.ToLower(partialID) // Case-insensitive matching

	for i := range conf.Webhooks {
		wh := &conf.Webhooks[i]
		// Check if ID or Name contains the partialID
		if strings.Contains(strings.ToLower(wh.ID), lowerPartialID) ||
			strings.Contains(strings.ToLower(wh.Name), lowerPartialID) {
			matches = append(matches, wh)
		}
	}
	return matches
}

// --- Cobra CLI Commands ---

var rootCmd = &cobra.Command{
	Use:   "cicd", // Renamed executable reference
	Short: "A CLI tool to manage CI/CD webhooks.",
	Long: `cicd is a versatile CLI tool designed to simplify the management
of CI/CD webhooks. It allows you to define webhooks, execute custom scripts
upon trigger, send email notifications, and run a local server to listen for
incoming requests.`,
}

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new webhook configuration",
	Long: `This command guides you through the process of adding a new webhook.
The webhook ID will be automatically generated.`,
	Run: func(cmd *cobra.Command, args []string) {
		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Enter webhook name: ")
		name, _ := reader.ReadString('\n')
		name = strings.TrimSpace(name)
		if name == "" {
			fmt.Println("Webhook name cannot be empty. Aborting.")
			return
		}

		fmt.Print("Enter script to execute (multi-line, end with 'EOF' on a new line): \n")
		scriptLines := []string{}
		for {
			line, _ := reader.ReadString('\n')
			if strings.TrimSpace(line) == "EOF" {
				break
			}
			scriptLines = append(scriptLines, line)
		}
		script := strings.TrimSpace(strings.Join(scriptLines, ""))
		if script == "" {
			fmt.Println("Script cannot be empty. Aborting.")
			return
		}

		fmt.Print("Enter comma-separated email recipients for notifications (leave blank if none): ")
		emailStr, _ := reader.ReadString('\n')
		emails := []string{}
		if strings.TrimSpace(emailStr) != "" {
			for _, email := range strings.Split(strings.TrimSpace(emailStr), ",") {
				emails = append(emails, strings.TrimSpace(email))
			}
		}

		newWebhook := Webhook{
			ID:      uuid.New().String(),
			Name:    name,
			URLPath: webhookBaseURL, // Fixed URL path for display/reference
			Script:  script,
			Emails:  emails,
		}

		conf := loadConfig()
		conf.Webhooks = append(conf.Webhooks, newWebhook)
		if err := saveConfig(conf); err != nil {
			fmt.Printf("Failed to save webhook: %v\n", err)
			return
		}

		fmt.Printf("Webhook '%s' added successfully with ID: %s\n", newWebhook.Name, newWebhook.ID)
		fmt.Printf("To hit this webhook, use POST to http://<your-public-ip>:%d%s?id=%s\n", defaultListenPort, webhookBaseURL, newWebhook.ID)
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configured webhooks",
	Long:  `Displays a detailed list of all webhooks currently configured in the system.`,
	Run: func(cmd *cobra.Command, args []string) {
		conf := loadConfig()

		if len(conf.Webhooks) == 0 {
			fmt.Println("No webhooks configured yet. Use 'cicd add' to add one.")
			return
		}

		fmt.Println("--- Configured Webhooks ---")
		for _, wh := range conf.Webhooks {
			fmt.Printf("ID:        %s\n", wh.ID)
			fmt.Printf("Name:      %s\n", wh.Name)
			hitURL := fmt.Sprintf("POST to http://<ip>:%d%s?id=%s", defaultListenPort, webhookBaseURL, wh.ID)
			fmt.Printf("Hit URL:   %s\n", hitURL)
			fmt.Printf("Emails:    %s\n", strings.Join(wh.Emails, ", "))
			fmt.Printf("Script:\n%s\n", wh.Script)
			fmt.Println(strings.Repeat("-", 40))
		}
	},
}

var deleteCmd = &cobra.Command{
	Use:   "delete <partial_id_or_name>",
	Short: "Delete a webhook configuration by partial ID or name",
	Long: `Deletes a specific webhook configuration. You can provide a partial ID or name.
If multiple matches are found, you'll be prompted to be more specific.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		searchTerm := args[0]
		conf := loadConfig()
		matches := findWebhookByPartialID(searchTerm, conf)

		if len(matches) == 0 {
			fmt.Printf("No webhook found matching '%s'.\n", searchTerm)
			return
		}
		if len(matches) > 1 {
			fmt.Printf("Multiple webhooks found matching '%s':\n", searchTerm)
			for _, m := range matches {
				fmt.Printf("  - ID: %s, Name: %s\n", m.ID, m.Name)
			}
			fmt.Println("Please provide a more specific ID or name.")
			return
		}

		// Exactly one match found
		webhookToDelete := matches[0]
		newWebhooks := []Webhook{}
		for _, wh := range conf.Webhooks {
			if wh.ID == webhookToDelete.ID {
				continue // Skip this webhook to delete it
			}
			newWebhooks = append(newWebhooks, wh)
		}

		conf.Webhooks = newWebhooks
		if err := saveConfig(conf); err != nil {
			fmt.Printf("Failed to delete webhook: %v\n", err)
			return
		}

		fmt.Printf("Webhook '%s' (ID: %s) deleted successfully.\n", webhookToDelete.Name, webhookToDelete.ID)
	},
}

var editCmd = &cobra.Command{
	Use:   "edit <partial_id_or_name>",
	Short: "Edit an existing webhook configuration by partial ID or name",
	Long: `Edits an existing webhook. You can provide a partial ID or name.
If multiple matches are found, you'll be prompted to be more specific.
The URL path is fixed to ` + webhookBaseURL + `.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		searchTerm := args[0]
		conf := loadConfig()
		matches := findWebhookByPartialID(searchTerm, conf)
		reader := bufio.NewReader(os.Stdin)

		if len(matches) == 0 {
			fmt.Printf("No webhook found matching '%s'.\n", searchTerm)
			return
		}
		if len(matches) > 1 {
			fmt.Printf("Multiple webhooks found matching '%s':\n", searchTerm)
			for _, m := range matches {
				fmt.Printf("  - ID: %s, Name: %s\n", m.ID, m.Name)
			}
			fmt.Println("Please provide a more specific ID or name.")
			return
		}

		// Exactly one match found
		webhookToEdit := matches[0]
		fmt.Printf("Editing webhook with ID: %s (Name: %s)\n", webhookToEdit.ID, webhookToEdit.Name)

		// Find the index of the webhook to edit in the actual slice
		idx := -1
		for i := range conf.Webhooks {
			if conf.Webhooks[i].ID == webhookToEdit.ID {
				idx = i
				break
			}
		}
		if idx == -1 {
			fmt.Println("Error: Webhook not found in configuration list (internal error).")
			return
		}

		fmt.Printf("Enter new webhook name (current: %s): ", conf.Webhooks[idx].Name)
		newName, _ := reader.ReadString('\n')
		newName = strings.TrimSpace(newName)
		if newName != "" {
			conf.Webhooks[idx].Name = newName
		}

		fmt.Printf("Enter new script (current:\n%s\n) (multi-line, end with 'EOF' on a new line; leave blank to keep current): \n", conf.Webhooks[idx].Script)
		scriptLines := []string{}
		for {
			line, _ := reader.ReadString('\n')
			if strings.TrimSpace(line) == "EOF" {
				break
			}
			scriptLines = append(scriptLines, line)
		}
		newScript := strings.TrimSpace(strings.Join(scriptLines, ""))
		if newScript != "" {
			conf.Webhooks[idx].Script = newScript
		}

		fmt.Printf("Enter new comma-separated email recipients (current: %s) (leave blank to keep current): ", strings.Join(conf.Webhooks[idx].Emails, ", "))
		newEmailStr, _ := reader.ReadString('\n')
		if strings.TrimSpace(newEmailStr) != "" {
			newEmails := []string{}
			for _, email := range strings.Split(strings.TrimSpace(newEmailStr), ",") {
				newEmails = append(newEmails, strings.TrimSpace(email))
			}
			conf.Webhooks[idx].Emails = newEmails
		}

		if err := saveConfig(conf); err != nil {
			fmt.Printf("Failed to save edited webhook: %v\n", err)
			return
		}

		fmt.Printf("Webhook with ID '%s' updated successfully.\n", conf.Webhooks[idx].ID)
	},
}

var copyCmd = &cobra.Command{
	Use:   "copy <partial_id_or_name>",
	Short: "Copy an existing webhook configuration by partial ID or name",
	Long: `Creates a new webhook configuration by copying an existing one.
You can provide a partial ID or name. If multiple matches are found, you'll be prompted to be more specific.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		searchTerm := args[0]
		conf := loadConfig()
		matches := findWebhookByPartialID(searchTerm, conf)

		if len(matches) == 0 {
			fmt.Printf("No webhook found matching '%s'.\n", searchTerm)
			return
		}
		if len(matches) > 1 {
			fmt.Printf("Multiple webhooks found matching '%s':\n", searchTerm)
			for _, m := range matches {
				fmt.Printf("  - ID: %s, Name: %s\n", m.ID, m.Name)
			}
			fmt.Println("Please provide a more specific ID or name.")
			return
		}

		// Exactly one match found
		webhookToCopy := matches[0]
		// Append a timestamp to the name for better uniqueness and clarity
		newWebhookName := fmt.Sprintf("Copy of %s (%s)", webhookToCopy.Name, time.Now().Format("20060102_150405"))
		newWebhook := Webhook{
			ID:      uuid.New().String(),
			Name:    newWebhookName,
			URLPath: webhookBaseURL,
			Script:  webhookToCopy.Script,
			Emails:  append([]string{}, webhookToCopy.Emails...),
		}
		conf.Webhooks = append(conf.Webhooks, newWebhook)
		if err := saveConfig(conf); err != nil {
			fmt.Printf("Failed to copy webhook: %v\n", err)
			return
		}
		fmt.Printf("Webhook '%s' (ID: %s) copied to new webhook '%s' (ID: %s).\n", webhookToCopy.Name, webhookToCopy.ID, newWebhook.Name, newWebhook.ID)
		fmt.Printf("To hit this new webhook, use POST to http://<your-public-ip>:%d%s?id=%s\n", defaultListenPort, webhookBaseURL, newWebhook.ID)
	},
}

var testCmd = &cobra.Command{
	Use:   "test <partial_id_or_name>",
	Short: "Test a webhook's script execution by partial ID or name",
	Long: `Executes the script associated with a given webhook. You can provide a partial ID or name.
If multiple matches are found, you'll be prompted to be more specific.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		searchTerm := args[0]
		conf := loadConfig()
		matches := findWebhookByPartialID(searchTerm, conf)

		if len(matches) == 0 {
			fmt.Printf("No webhook found matching '%s'.\n", searchTerm)
			return
		}
		if len(matches) > 1 {
			fmt.Printf("Multiple webhooks found matching '%s':\n", searchTerm)
			for _, m := range matches {
				fmt.Printf("  - ID: %s, Name: %s\n", m.ID, m.Name)
			}
			fmt.Println("Please provide a more specific ID or name.")
			return
		}

		// Exactly one match found
		webhookToTest := matches[0]
		fmt.Printf("Testing script for webhook '%s' (ID: %s):\n", webhookToTest.Name, webhookToTest.ID)
		fmt.Println(strings.Repeat("=", 40))
		fmt.Println(webhookToTest.Script)
		fmt.Println(strings.Repeat("=", 40))

		shell := "bash"
		shellArg := "-c"
		if runtime.GOOS == "windows" {
			shell = "cmd.exe"
			shellArg = "/C"
		}

		execCmd := exec.Command(shell, shellArg, webhookToTest.Script)
		output, err := execCmd.CombinedOutput()

		fmt.Println("\n--- Script Output ---")
		fmt.Println(string(output))
		fmt.Println("---------------------")

		if err != nil {
			fmt.Printf("Script finished with error: %v\n", err)
		} else {
			fmt.Println("Script executed successfully.")
		}
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage global application configuration",
	Long:  `This command provides subcommands to configure global settings for the webhook tool, such as email settings.`,
}

var configEmailCmd = &cobra.Command{
	Use:   "email",
	Short: "Configure email settings for notifications",
	Long: `Set up the sender email address, app password, SMTP server, and port
to enable email notifications for webhooks.`,
	Run: func(cmd *cobra.Command, args []string) {
		reader := bufio.NewReader(os.Stdin)
		conf := loadConfig()

		fmt.Println("\n--- Current Email Configuration ---")
		fmt.Printf("Sender Email: %s\n", conf.Email.SenderEmail)
		fmt.Printf("SMTP Server:  %s\n", conf.Email.SMTPServer)
		fmt.Printf("SMTP Port:    %d\n", conf.Email.SMTPPort)
		fmt.Println(strings.Repeat("-", 35))

		fmt.Printf("Enter sender email (current: %s): ", conf.Email.SenderEmail)
		senderEmail, _ := reader.ReadString('\n')
		senderEmail = strings.TrimSpace(senderEmail)
		if senderEmail != "" {
			conf.Email.SenderEmail = senderEmail
		}

		displayPassword := strings.Repeat("*", len(conf.Email.AppPassword))
		if len(conf.Email.AppPassword) == 0 {
			displayPassword = "<not set>"
		}
		fmt.Printf("Enter email app password (current: %s): ", displayPassword)
		appPassword, _ := reader.ReadString('\n')
		appPassword = strings.TrimSpace(appPassword)
		if appPassword != "" {
			conf.Email.AppPassword = appPassword
		}

		fmt.Printf("Enter SMTP server (e.g., smtp.gmail.com) (current: %s): ", conf.Email.SMTPServer)
		smtpServerInput, _ := reader.ReadString('\n')
		smtpServerInput = strings.TrimSpace(smtpServerInput)
		if smtpServerInput != "" {
			conf.Email.SMTPServer = smtpServerInput
		}

		fmt.Printf("Enter SMTP port (e.g., 587 or 465) (current: %d): ", conf.Email.SMTPPort)
		smtpPortStr, _ := reader.ReadString('\n')
		smtpPortStr = strings.TrimSpace(smtpPortStr)
		if smtpPortStr != "" {
			var smtpPort int
			_, err := fmt.Sscanf(smtpPortStr, "%d", &smtpPort)
			if err != nil {
				fmt.Printf("Invalid port number: %v. Keeping current port.\n", err)
			} else {
				conf.Email.SMTPPort = smtpPort
			}
		}

		if err := saveConfig(conf); err != nil {
			fmt.Printf("Failed to save email configuration: %v\n", err)
			return
		}

		fmt.Println("Email configuration updated successfully.")
	},
}

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Manage webhook execution logs and main server logs",
	Long:  `This command provides subcommands to view and manage webhook execution logs and the main application server log.`,
}

var logsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all webhook log files",
	Long:  `Lists the log files for all configured webhooks.`,
	Run: func(cmd *cobra.Command, args []string) {
		conf := loadConfig()
		if len(conf.Webhooks) == 0 {
			fmt.Println("No webhooks configured. No webhook log files to list.")
			return
		}

		fmt.Println("--- Webhook Log Files ---")
		foundLogs := false
		for _, wh := range conf.Webhooks {
			logFilePath := getWebhookLogFilePath(wh.ID)
			if _, err := os.Stat(logFilePath); err == nil {
				fmt.Printf("Webhook '%s' (ID: %s): %s\n", wh.Name, wh.ID, logFilePath)
				foundLogs = true
			}
		}
		if !foundLogs {
			fmt.Println("No webhook log files found for configured webhooks yet. They will be created when webhooks are triggered.")
		}
		fmt.Println("-------------------------")
	},
}

var logsShowCmd = &cobra.Command{
	Use:   "show <partial_id_or_name>",
	Short: "Show the content of a webhook's log file",
	Long: `Displays the content of the log file for a specific webhook.
You can provide a partial ID or name. If multiple matches are found, you'll be prompted to be more specific.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		searchTerm := args[0]
		conf := loadConfig()
		matches := findWebhookByPartialID(searchTerm, conf)

		if len(matches) == 0 {
			fmt.Printf("No webhook found matching '%s'.\n", searchTerm)
			return
		}
		if len(matches) > 1 {
			fmt.Printf("Multiple webhooks found matching '%s':\n", searchTerm)
			for _, m := range matches {
				fmt.Printf("  - ID: %s, Name: %s\n", m.ID, m.Name)
			}
			fmt.Println("Please provide a more specific ID or name.")
			return
		}

		webhookToView := matches[0]
		logFilePath := getWebhookLogFilePath(webhookToView.ID)

		fmt.Printf("--- Log for Webhook '%s' (ID: %s) ---\n", webhookToView.Name, webhookToView.ID)
		data, err := os.ReadFile(logFilePath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("No log file found for this webhook at %s.\n", logFilePath)
			} else {
				fmt.Printf("Error reading log file %s: %v\n", logFilePath, err)
			}
			return
		}
		fmt.Println(string(data))
		fmt.Println("-------------------------------------")
	},
}

var logsFlushCmd = &cobra.Command{
	Use:   "flush <partial_id_or_name>",
	Short: "Clear the content of a webhook's log file",
	Long: `Clears (empties) the log file for a specific webhook.
You can provide a partial ID or name. If multiple matches are found, you'll be prompted to be more specific.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		searchTerm := args[0]
		conf := loadConfig()
		matches := findWebhookByPartialID(searchTerm, conf)

		if len(matches) == 0 {
			fmt.Printf("No webhook found matching '%s'.\n", searchTerm)
			return
		}
		if len(matches) > 1 {
			fmt.Printf("Multiple webhooks found matching '%s':\n", searchTerm)
			for _, m := range matches {
				fmt.Printf("  - ID: %s, Name: %s\n", m.ID, m.Name)
			}
			fmt.Println("Please provide a more specific ID or name.")
			return
		}

		webhookToFlush := matches[0]
		logFilePath := getWebhookLogFilePath(webhookToFlush.ID)

		// Create an empty file, effectively clearing it
		file, err := os.Create(logFilePath)
		if err != nil {
			fmt.Printf("Error flushing log file %s: %v\n", logFilePath, err)
			return
		}
		file.Close()
		fmt.Printf("Log file for webhook '%s' (ID: %s) flushed successfully.\n", webhookToFlush.Name, webhookToFlush.ID)
	},
}

var logsServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Show the content of the main application log file",
	Long:  `Displays the content of the 'cicd.log' file, which contains general messages from the webhook server (startup, shutdown, etc.).`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("--- Main Application Log (%s) ---\n", mainLogFileName)
		data, err := os.ReadFile(mainLogFilePath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("No main application log file found at %s. It will be created when the server starts.\n", mainLogFilePath)
			} else {
				fmt.Printf("Error reading main application log file %s: %v\n", mainLogFilePath, err)
			}
			return
		}
		fmt.Println(string(data))
		fmt.Println("---------------------------------")
	},
}

var logsFlushServerCmd = &cobra.Command{
	Use:   "flush-server",
	Short: "Clear the content of the main application log file",
	Long:  `Clears (empties) the 'cicd.log' file, which contains general messages from the webhook server.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Create an empty file, effectively clearing it
		file, err := os.Create(mainLogFilePath)
		if err != nil {
			fmt.Printf("Error flushing main application log file %s: %v\n", mainLogFilePath, err)
			return
		}
		file.Close()
		fmt.Printf("Main application log file (%s) flushed successfully.\n", mainLogFileName)
	},
}

// startServerRunner is a common function for start and launch commands
func startServerRunner(cmd *cobra.Command, args []string) {
	conf := loadConfig()
	if len(conf.Webhooks) == 0 {
		fmt.Println("No webhooks configured. Please add webhooks using 'cicd add' before starting the server.")
		return
	}

	var portToUse int
	var err error
	if cmd.Flags().Changed("port") {
		portToUse, err = cmd.Flags().GetInt("port")
		if err != nil {
			log.Fatalf("Invalid port value: %v", err)
		}
	} else {
		portToUse = defaultListenPort
		// Check if default port is free, if not, try to find a free one.
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", portToUse))
		if err != nil {
			log.Printf("Default port %d is in use. Trying to find a free port...", portToUse)
			p, findErr := findFreePort()
			if findErr != nil {
				log.Fatalf("Failed to find a free port: %v", findErr)
			}
			portToUse = p
		} else {
			listener.Close() // Close the listener immediately after checking
		}
	}

	fmt.Printf("Starting webhook server on port %d...\n", portToUse)
	go startServer(portToUse, conf)

	// Keep the main goroutine alive
	select {}
}

var startServerCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the webhook server in foreground or background",
	Long: fmt.Sprintf(`Starts the HTTP server to listen for incoming webhook requests.
Defaults to port %d. You can specify a different port using the -p flag.

By default, the server runs in the foreground. To run in the background:
  On Linux/macOS: nohup ./cicd start &
  On Windows (using cmd.exe): start /B cicd.exe start

All application-level logs (startup, shutdown, general errors) will be written
to %s.
`, defaultListenPort, mainLogFilePath),
	Run: startServerRunner,
}

var launchCmd = &cobra.Command{
	Use:   "launch",
	Short: "Launch the webhook server with a splash screen in foreground or background",
	Long: fmt.Sprintf(`Launches the HTTP server, similar to 'cicd start', but displays a cool ASCII art splash screen.
Defaults to port %d. You can specify a different port using the -p flag.

By default, the server runs in the foreground. To run in the background:
  On Linux/macOS: nohup ./cicd launch & (Splash screen output will go to nohup.out or %s)
  On Windows (using cmd.exe): start /B cicd.exe launch

All application-level logs (startup, shutdown, general errors) will be written
to %s.
`, defaultListenPort, mainLogFilePath, mainLogFilePath),
	Run: func(cmd *cobra.Command, args []string) {
		// Enhanced ASCII Art for CICD with shadows and 3D effect
		fmt.Println(" ")
		fmt.Println("     ██████╗ ██╗ ██████╗ ██████╗ ")
		fmt.Println("    ██╔════╝███║██╔════╝ ██╔═══██╗")
		fmt.Println("    ██║    ╚██║██║       ██║   ██║")
		fmt.Println("    ██║     ██║██║       ██║   ██║")
		fmt.Println("    ╚██████╗ ██║╚██████╗╚██████╔╝")
		fmt.Println("     ╚═════╝ ╚═╝ ╚═════╝ ╚═════╝ ")
		fmt.Println("     ░░░░░░░░░░░░░░░░░░░░░░░░░░░░ ")
		fmt.Println(" ")
		fmt.Println("      ░█▀▀░█▀█░█▀▄░█▀▀░█▀▀░▀█▀░█▀▀")
		fmt.Println("      ░█▀▀░█░█░█▀▄░█▀▀░▀▀█░░█░░▀▀█")
		fmt.Println("      ░▀░░░▀▀▀░▀░▀░▀▀▀░▀▀▀░░▀░░▀▀▀")
		fmt.Println(" ")
		fmt.Println("      Webhook Server - 🚀 Launched! 🚀")
		fmt.Println(" ")
		fmt.Println("                -PulpBeater")
		fmt.Println(" ")
		startServerRunner(cmd, args) // Call the common server start logic
	},
}

var stopServerCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the webhook server (if running in current process)",
	Long: `Attempts to gracefully stop the webhook server if it was started by this process.
If the server was started as a background process (e.g., using 'nohup' or 'start /B'),
this command will not terminate it directly. You'll need to manually terminate the background process:

  1. Find the Process ID (PID):
     On Linux/macOS: ps aux | grep cicd | grep -v grep
     On Windows: tasklist | findstr /I "cicd.exe"
  2. Terminate the process using its PID:
     On Linux/macOS: kill <PID>
     On Windows: taskkill /F /PID <PID>`,
	Run: func(cmd *cobra.Command, args []string) {
		if server != nil {
			stopServer()
			fmt.Println("Server stop command issued. Check logs for confirmation.")
		} else {
			fmt.Println("No server instance found running in this process.")
			fmt.Println("\n--- To stop a background server process manually: ---")
			fmt.Println("  1. Find the Process ID (PID):")
			fmt.Println("     On Linux/macOS: ps aux | grep cicd | grep -v grep")
			fmt.Println("     On Windows: tasklist | findstr /I \"cicd.exe\"")
			fmt.Println("  2. Terminate the process using its PID:")
			fmt.Println("     On Linux/macOS: kill <PID>")
			fmt.Println("     On Windows: taskkill /F /PID <PID>")
			fmt.Println("--------------------------------------------------")
		}
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display the application version",
	Long:  `Displays the current version of the CI/CD webhook tool.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("CI/CD Webhook Tool Version: %s\n", AppVersion)
	},
}

func init() {
	initConfig() // Initialize config and log paths on startup

	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(editCmd)
	rootCmd.AddCommand(copyCmd)
	rootCmd.AddCommand(testCmd)

	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configEmailCmd)

	rootCmd.AddCommand(logsCmd) // Add the new logs command
	logsCmd.AddCommand(logsListCmd)
	logsCmd.AddCommand(logsShowCmd)
	logsCmd.AddCommand(logsFlushCmd)
	logsCmd.AddCommand(logsServerCmd)     // Add new subcommand for main log
	logsCmd.AddCommand(logsFlushServerCmd) // Add new subcommand for flushing main log

	rootCmd.AddCommand(startServerCmd)
	startServerCmd.Flags().IntVarP(&serverPort, "port", "p", defaultListenPort, "Port to run the webhook server on")

	rootCmd.AddCommand(launchCmd) // Add the new launch command
	launchCmd.Flags().IntVarP(&serverPort, "port", "p", defaultListenPort, "Port to run the webhook server on") // Add flags for launch too

	rootCmd.AddCommand(stopServerCmd)
	rootCmd.AddCommand(versionCmd) // Add the new version command
}

func main() {
	// Setup logging to a file and stderr/stdout
	logFile, err := os.OpenFile(mainLogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open main log file %s: %v", mainLogFilePath, err)
	}
	defer logFile.Close()

	// Direct log output to both console and the main log file
	mw := io.MultiWriter(os.Stderr, logFile)
	log.SetOutput(mw)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile) // Add file/line info to logs

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
		os.Exit(1)
	}
}

