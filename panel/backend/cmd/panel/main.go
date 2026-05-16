package main

import (
	"embed"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ParsaKSH/spoof-tunnel/panel/internal/api"
	"github.com/ParsaKSH/spoof-tunnel/panel/internal/auth"
	"github.com/ParsaKSH/spoof-tunnel/panel/internal/db"
	"github.com/ParsaKSH/spoof-tunnel/panel/internal/manager"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

//go:embed all:web
var webFS embed.FS

func main() {
	port := flag.Int("port", 0, "panel port (0 = auto from DB or random)")
	setup := flag.Bool("setup", false, "run initial setup with random credentials")
	setupUser := flag.String("setup-user", "", "setup: admin username")
	setupPass := flag.String("setup-pass", "", "setup: admin password")
	setupPort := flag.Int("setup-port", 0, "setup: panel port")
	flag.Parse()

	// Determine data directory
	dataDir := "/etc/spoof-panel"
	if os.Getenv("SPOOF_DATA_DIR") != "" {
		dataDir = os.Getenv("SPOOF_DATA_DIR")
	}
	os.MkdirAll(dataDir, 0755)

	dbPath := filepath.Join(dataDir, "panel.db")
	log.Printf("Database: %s", dbPath)

	// Init database
	database, err := db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("Failed to init database: %v", err)
	}

	// Handle setup mode
	if *setup || *setupUser != "" {
		runSetup(database, *setupUser, *setupPass, *setupPort)
		return
	}

	// Determine spoof binary path
	binaryPath := filepath.Join(dataDir, "spoof")
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		if p, err := exec.LookPath("spoof"); err == nil {
			binaryPath = p
		}
	}

	// Determine web path (random secret URL prefix)
	webPath := getOrCreateSetting(database, "web_path", func() string {
		return auth.GenerateRandomString(10)
	})

	// Create tunnel manager
	mgr := manager.NewManager(database, binaryPath, dataDir)

	// Create API server — API is prefixed with /{webpath}/api
	srv := api.NewServer(database, mgr, "/"+webPath)

	// Auto-start enabled tunnels
	var tunnels []db.TunnelInstance
	if err := database.Where("enabled = ?", true).Find(&tunnels).Error; err == nil {
		for _, t := range tunnels {
			log.Printf("Auto-starting tunnel: %s", t.Name)
			mgr.StartInstance(t.ID)
		}
	}

	// Serve embedded frontend
	webRoot, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("embedded web: %v", err)
	}

	// Custom file server
	serveFile := func(c *gin.Context, filePath string) bool {
		f, err := webRoot.Open(filePath)
		if err != nil {
			return false
		}
		defer f.Close()

		stat, err := f.Stat()
		if err != nil || stat.IsDir() {
			return false
		}

		ext := filepath.Ext(filePath)
		contentType := ""
		switch ext {
		case ".html":
			contentType = "text/html; charset=utf-8"
		case ".css":
			contentType = "text/css; charset=utf-8"
		case ".js":
			contentType = "application/javascript; charset=utf-8"
		case ".json":
			contentType = "application/json"
		case ".png":
			contentType = "image/png"
		case ".svg":
			contentType = "image/svg+xml"
		case ".ico":
			contentType = "image/x-icon"
		case ".woff2":
			contentType = "font/woff2"
		case ".woff":
			contentType = "font/woff"
		case ".txt":
			contentType = "text/plain"
		case ".map":
			contentType = "application/json"
		default:
			contentType = "application/octet-stream"
		}

		data, err := io.ReadAll(f)
		if err != nil {
			return false
		}

		c.Data(http.StatusOK, contentType, data)
		return true
	}

	// All routes require /{webpath}/ prefix
	prefix := "/" + webPath
	srv.Router().NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path

		// Root → redirect to /{webpath}/
		if path == "/" || path == "" {
			c.Redirect(http.StatusFound, prefix+"/")
			return
		}

		// Allow /_next/static assets from root (Next.js hardcodes these paths)
		if strings.HasPrefix(path, "/_next/") {
			filePath := path[1:] // remove leading /
			if serveFile(c, filePath) {
				return
			}
		}

		// Must start with /{webpath}
		if !strings.HasPrefix(path, prefix) {
			c.String(http.StatusNotFound, "not found")
			return
		}

		// Strip prefix to get the actual file/page path
		relPath := strings.TrimPrefix(path, prefix)
		relPath = strings.TrimPrefix(relPath, "/")

		if relPath != "" {
			if serveFile(c, relPath) {
				return
			}
			if serveFile(c, relPath+"/index.html") {
				return
			}
			cleaned := strings.TrimSuffix(relPath, "/")
			if cleaned != relPath {
				if serveFile(c, cleaned) {
					return
				}
				if serveFile(c, cleaned+"/index.html") {
					return
				}
			}
		}

		// SPA fallback
		serveFile(c, "index.html")
	})

	// Determine port
	listenPort := *port
	if listenPort == 0 {
		var setting db.Setting
		if err := database.Where("key = ?", "panel_port").First(&setting).Error; err == nil {
			fmt.Sscanf(setting.Value, "%d", &listenPort)
		}
	}
	if listenPort == 0 {
		listenPort = auth.GenerateRandomPort()
		database.Create(&db.Setting{Key: "panel_port", Value: fmt.Sprintf("%d", listenPort)})
	}

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		mgr.StopAll()
		os.Exit(0)
	}()

	addr := fmt.Sprintf("0.0.0.0:%d", listenPort)
	fullURL := fmt.Sprintf("http://0.0.0.0:%d/%s/", listenPort, webPath)
	log.Printf("╔══════════════════════════════════════════════════╗")
	log.Printf("║         Spoof Panel v3.0.2                       ║")
	log.Printf("║  %-48s║", fullURL)
	log.Printf("╚══════════════════════════════════════════════════╝")

	if err := srv.Router().Run(addr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// getOrCreateSetting reads a setting from DB, or creates it with a default value
func getOrCreateSetting(database *gorm.DB, key string, defaultFn func() string) string {
	var setting db.Setting
	if err := database.Where("key = ?", key).First(&setting).Error; err == nil {
		return setting.Value
	}
	value := defaultFn()
	database.Create(&db.Setting{Key: key, Value: value})
	return value
}

func runSetup(database *gorm.DB, username, password string, port int) {
	if username == "" {
		username = auth.GenerateRandomString(8)
	}
	if password == "" {
		password = auth.GenerateRandomString(12)
	}
	if port == 0 {
		port = auth.GenerateRandomPort()
	}

	hash, _ := auth.HashPassword(password)
	database.Create(&db.User{
		Username:     username,
		PasswordHash: hash,
	})

	database.Create(&db.Setting{Key: "panel_port", Value: fmt.Sprintf("%d", port)})

	// Generate web path if not exists
	webPath := getOrCreateSetting(database, "web_path", func() string {
		return auth.GenerateRandomString(10)
	})

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║       Spoof Panel — Setup Complete               ║")
	fmt.Println("╠══════════════════════════════════════════════════╣")
	fmt.Printf("║  Port:     %-38d║\n", port)
	fmt.Printf("║  Username: %-38s║\n", username)
	fmt.Printf("║  Password: %-38s║\n", password)
	fmt.Printf("║  Web Path: %-38s║\n", "/"+webPath)
	fmt.Println("╠══════════════════════════════════════════════════╣")
	fmt.Printf("║  URL: http://YOUR_IP:%d/%s/\n", port, webPath)
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()
}
