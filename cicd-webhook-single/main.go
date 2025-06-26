// main.go
package main

import (
	"bufio"
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
const configFileName = "config.json"
const webhookBaseURL = "/webhook"
const statusURL = "/status"
const defaultListenPort = 52606 // Fixed default port

var (
	configPath    string
	configOnce    sync.Once
	currentConfig *Configuration
	server        *http.Server
	doneCh        = make(chan struct{}) // Channel to signal server shutdown completion
	serverPort    int                   // Store the port the server is running on
)

// --- Configuration Management Functions ---

// initConfig ensures the config directory exists and determines the config file path.
func initConfig() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Warning: Could not determine user home directory: %v. Using current directory for config.\n", err)
		homeDir = "."
	}

	configDir := filepath.Join(homeDir, ".cicd-webhook")
	configPath = filepath.Join(configDir, configFileName)

	if err := os.MkdirAll(configDir, 0700); err != nil {
		fmt.Printf("Warning: Could not create config directory %s: %v. Errors might occur.\n", configDir, err)
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

		go func(wh Webhook, scriptEnv []string) {
			log.Printf("Executing script for webhook '%s'. Parameters available as environment variables: %s\n", wh.Name, paramDisplay)

			shell := "bash"
			shellArg := "-c"
			if runtime.GOOS == "windows" {
				shell = "cmd.exe"
				shellArg = "/C"
			}

			execCmd := exec.Command(shell, shellArg, wh.Script)
			execCmd.Env = scriptEnv

			output, err := execCmd.CombinedOutput()
			scriptOutput := string(output)
			status := "SUCCESS"
			errorMessage := ""

			if err != nil {
				status = "FAILED"
				errorMessage = fmt.Sprintf("Error: %v", err)
				log.Printf("Script execution for '%s' FAILED: %v\nOutput:\n%s\n", wh.Name, err, scriptOutput)
			} else {
				log.Printf("Script execution for '%s' SUCCESS.\nOutput:\n%s\n", wh.Name, scriptOutput)
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
					wh.Name, wh.ID, status, time.Now().Format(time.RFC3339), r.RemoteAddr,
					string(body), paramDisplay, scriptOutput, errorMessage)

				if err := sendEmail(conf.Email, wh.Emails, emailSubject, emailBody); err != nil {
					log.Printf("Error sending email for webhook '%s': %v\n", wh.Name, err)
				} else {
					log.Printf("Email notification sent for webhook '%s' successfully.\n", wh.Name)
				}
			}
		}(*foundWebhook, envVars)

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
		fmt.Println("If the server was started in the background (e.g., with '&' on Linux/macOS or 'start /B' on Windows),")
		fmt.Println("you will need to terminate its process manually (e.g., using 'taskkill /F /PID <PID>' on Windows or 'kill <PID>' on Linux/macOS).")
		fmt.Println("You can find the PID using 'tasklist | findstr cicd.exe' on Windows or 'ps aux | grep cicd' on Linux/macOS.")
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
			fmt.Printf("ID:       %s\n", wh.ID)
			fmt.Printf("Name:     %s\n", wh.Name)
			hitURL := fmt.Sprintf("POST to http://<ip>:%d%s?id=%s", defaultListenPort, webhookBaseURL, wh.ID)
			fmt.Printf("Hit URL:  %s\n", hitURL)
			fmt.Printf("Emails:   %s\n", strings.Join(wh.Emails, ", "))
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
		newWebhook := Webhook{
			ID:      uuid.New().String(),
			Name:    "Copy of " + webhookToCopy.Name,
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
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", portToUse))
		if err != nil {
			log.Printf("Default port %d is in use. Trying to find a free port...", portToUse)
			p, findErr := findFreePort()
			if findErr != nil {
				log.Fatalf("Failed to find a free port: %v", findErr)
			}
			portToUse = p
		} else {
			listener.Close()
		}
	}

	fmt.Printf("Starting webhook server on port %d...\n", portToUse)
	go startServer(portToUse, conf)

	select {}
}

var startServerCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the webhook server",
	Long: fmt.Sprintf(`Starts the HTTP server to listen for incoming webhook requests.
Defaults to port %d. You can specify a different port using the -p flag.`, defaultListenPort),
	Run: startServerRunner,
}

var launchCmd = &cobra.Command{
	Use:   "launch",
	Short: "Launch the webhook server with a splash screen",
	Long: fmt.Sprintf(`Launches the HTTP server, similar to 'cicd start', but displays a cool ASCII art splash screen.
Defaults to port %d. You can specify a different port using the -p flag.`, defaultListenPort),
	Run: func(cmd *cobra.Command, args []string) {
		// Enhanced ASCII Art for CICD with shadows and 3D effect
		fmt.Println(" ")
		fmt.Println("      ██████╗ ██╗ ██████╗██████╗ ")
		fmt.Println("     ██╔════╝███║██╔════╝╚════██╗")
		fmt.Println("     ██║     ╚██║██║      █████╔╝")
		fmt.Println("     ██║      ██║██║     ██╔═══╝ ")
		fmt.Println("     ╚██████╗ ██║╚██████╗███████╗")
		fmt.Println("      ╚═════╝ ╚═╝ ╚═════╝╚══════╝")
		fmt.Println("     ░░░░░░░░░░░░░░░░░░░░░░░░░░░░")
		fmt.Println(" ")
		fmt.Println("      ░█▀▀░█▀█░█▀▄░█▀▀░█▀▀░▀█▀░█▀▀")
		fmt.Println("      ░█▀▀░█░█░█▀▄░█▀▀░▀▀█░░█░░▀▀█")
		fmt.Println("      ░▀░░░▀▀▀░▀░▀░▀▀▀░▀▀▀░░▀░░▀▀▀")
		fmt.Println(" ")
		fmt.Println("      Webhook Server - 🚀 Launched! 🚀")
		fmt.Println(" ")
		fmt.Println("                          -PulpBeater")
		fmt.Println(" ")
		startServerRunner(cmd, args) // Call the common server start logic
	},
}

var stopServerCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the webhook server (if running in current process)",
	Long: `Attempts to gracefully stop the webhook server if it was started by this process.
Note: This command will only work if the server was started in the same terminal session
and the process ID matches. If the server was started as a background process (e.g., using '&' or 'start /B'),
this command will not terminate it. You'll need to manually terminate the background process.`,
	Run: func(cmd *cobra.Command, args []string) {
		if server != nil {
			stopServer()
			fmt.Println("Server stop command issued. Check logs for confirmation.")
		} else {
			fmt.Println("No server instance found running in this process.")
			fmt.Println("If the server was started in the background (e.g., with '&' on Linux/macOS or 'start /B' on Windows),")
			fmt.Println("you will need to terminate its process manually (e.g., using 'taskkill /F /PID <PID>' on Windows or 'kill <PID>' on Linux/macOS).")
			fmt.Println("You can find the PID using 'tasklist | findstr cicd.exe' on Windows or 'ps aux | grep cicd' on Linux/macOS.")
		}
	},
}

func init() {
	initConfig() // Initialize config path on startup

	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(editCmd)
	rootCmd.AddCommand(copyCmd)
	rootCmd.AddCommand(testCmd)

	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configEmailCmd)

	rootCmd.AddCommand(startServerCmd)
	startServerCmd.Flags().IntVarP(&serverPort, "port", "p", defaultListenPort, "Port to run the webhook server on")

	rootCmd.AddCommand(launchCmd) // Add the new launch command
	launchCmd.Flags().IntVarP(&serverPort, "port", "p", defaultListenPort, "Port to run the webhook server on") // Add flags for launch too

	rootCmd.AddCommand(stopServerCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
		os.Exit(1)
	}
}

