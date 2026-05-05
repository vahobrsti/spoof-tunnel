package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ParsaKSH/spoof-tunnel/internal/tester"
	"github.com/ParsaKSH/spoof-tunnel/panel/internal/auth"
	"github.com/ParsaKSH/spoof-tunnel/panel/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// ── Auth Handlers ──

func (s *Server) handleAuthCheck(c *gin.Context) {
	var count int64
	s.db.Model(&db.User{}).Count(&count)
	c.JSON(http.StatusOK, gin.H{"needs_setup": count == 0})
}

func (s *Server) handleSetup(c *gin.Context) {
	var count int64
	s.db.Model(&db.User{}).Count(&count)
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "already set up"})
		return
	}

	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash failed"})
		return
	}

	user := db.User{
		Username:     req.Username,
		PasswordHash: hash,
	}
	if err := s.db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	token, _ := auth.GenerateToken(user.ID, user.Username)
	c.JSON(http.StatusOK, gin.H{"token": token, "username": user.Username})
}

func (s *Server) handleLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user db.User
	if err := s.db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if !auth.CheckPassword(req.Password, user.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Update last login
	s.db.Model(&user).Update("last_login", time.Now())

	token, err := auth.GenerateToken(user.ID, user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token, "username": user.Username})
}

func (s *Server) handleMe(c *gin.Context) {
	userID := c.GetUint("user_id")
	var user db.User
	s.db.First(&user, userID)
	c.JSON(http.StatusOK, user)
}

// ── Dashboard ──

func (s *Server) handleDashboard(c *gin.Context) {
	status, errMsg := s.manager.Status()
	uptime := s.manager.Uptime()

	c.JSON(http.StatusOK, gin.H{
		"tunnel_status": status,
		"tunnel_error":  errMsg,
		"uptime":        uptime.Seconds(),
	})
}

func (s *Server) handleSystem(c *gin.Context) {
	hostname, _ := os.Hostname()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	c.JSON(http.StatusOK, gin.H{
		"hostname":    hostname,
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"cpus":        runtime.NumCPU(),
		"goroutines":  runtime.NumGoroutine(),
		"memory_mb":   m.Alloc / 1024 / 1024,
		"go_version":  runtime.Version(),
	})
}

// ── Config Handlers ──

func (s *Server) handleGetConfig(c *gin.Context) {
	var cfg db.ServerConfig
	s.db.First(&cfg)
	c.JSON(http.StatusOK, cfg)
}

func (s *Server) handleUpdateConfig(c *gin.Context) {
	var cfg db.ServerConfig
	s.db.First(&cfg)

	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfg.ID = 1
	s.db.Save(&cfg)
	c.JSON(http.StatusOK, cfg)
}

// ── Tunnel Control ──

func (s *Server) handleTunnelStart(c *gin.Context) {
	if err := s.manager.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "started"})
}

func (s *Server) handleTunnelStop(c *gin.Context) {
	if err := s.manager.Stop(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "stopped"})
}

func (s *Server) handleTunnelRestart(c *gin.Context) {
	if err := s.manager.Restart(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "restarted"})
}

func (s *Server) handleTunnelStatus(c *gin.Context) {
	status, errMsg := s.manager.Status()
	c.JSON(http.StatusOK, gin.H{
		"status": status,
		"error":  errMsg,
		"uptime": s.manager.Uptime().Seconds(),
	})
}

// WebSocket log streaming
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func (s *Server) handleTunnelLogs(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// Send existing logs
	for _, line := range s.manager.GetLogs(100) {
		conn.WriteMessage(websocket.TextMessage, []byte(line))
	}

	// Stream new logs
	logCh := s.manager.LogChannel()
	for {
		select {
		case line, ok := <-logCh:
			if !ok {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
				return
			}
		}
	}
}

// ── Settings ──

func (s *Server) handleChangePassword(c *gin.Context) {
	userID := c.GetUint("user_id")
	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user db.User
	s.db.First(&user, userID)

	if !auth.CheckPassword(req.OldPassword, user.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "wrong password"})
		return
	}

	hash, _ := auth.HashPassword(req.NewPassword)
	s.db.Model(&user).Update("password_hash", hash)

	// Generate new token
	token, _ := auth.GenerateToken(user.ID, user.Username)
	c.JSON(http.StatusOK, gin.H{"ok": true, "token": token})
}

// ── Tester Handlers ──

func (s *Server) handleTesterStart(c *gin.Context) {
	var req struct {
		Mode          string  `json:"mode" binding:"required"`
		Protocol      string  `json:"protocol" binding:"required"`
		IPList        string  `json:"ip_list" binding:"required"`
		DstIP         string  `json:"dst_ip"`
		DstPort       int     `json:"dst_port"`
		Timeout       int     `json:"timeout"`
		PacketCount   int     `json:"packet_count"`
		MaxPacketLoss float64 `json:"max_packet_loss"`
		Concurrency   int     `json:"concurrency"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Parse IPs from text
	srcIPs, err := tester.ParseIPListFromString(req.IPList)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid IP list: " + err.Error()})
		return
	}

	if len(srcIPs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP list is empty"})
		return
	}

	cfg := tester.TesterConfig{
		Mode:          req.Mode,
		Protocol:      req.Protocol,
		DstIP:         req.DstIP,
		DstPort:       req.DstPort,
		Timeout:       req.Timeout,
		PacketCount:   req.PacketCount,
		MaxPacketLoss: req.MaxPacketLoss,
		Concurrency:   req.Concurrency,
	}

	switch req.Mode {
	case "sender":
		if err := s.tester.RunSender(cfg, srcIPs); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	case "receiver":
		if err := s.tester.RunReceiver(cfg, srcIPs); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "mode must be 'sender' or 'receiver'"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "started", "ip_count": len(srcIPs)})
}

func (s *Server) handleTesterStatus(c *gin.Context) {
	state := s.tester.State()
	c.JSON(http.StatusOK, state)
}

func (s *Server) handleTesterStop(c *gin.Context) {
	s.tester.Stop()
	c.JSON(http.StatusOK, gin.H{"status": "stopped"})
}

func (s *Server) handleTesterResults(c *gin.Context) {
	state := s.tester.State()
	c.JSON(http.StatusOK, gin.H{
		"status":  state.Status,
		"results": state.Results,
	})
}

func (s *Server) handleTesterDownload(c *gin.Context) {
	state := s.tester.State()
	if len(state.Results) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no results"})
		return
	}

	var lines []string
	for _, r := range state.Results {
		if r.Passed {
			lines = append(lines, r.IP)
		}
	}

	content := strings.Join(lines, "\n") + "\n"
	c.Header("Content-Disposition", "attachment; filename=spoof-ips.txt")
	c.Data(http.StatusOK, "text/plain", []byte(content))
}

func (s *Server) handleTesterUpload(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no file uploaded"})
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "read file: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"content": string(data),
	})
}

// ── Spoof IP File Management ──

func spoofIPFilePath() string {
	dataDir := os.Getenv("SPOOF_DATA_DIR")
	if dataDir == "" {
		dataDir = "/etc/spoof-panel"
	}
	return filepath.Join(dataDir, "spoof-ips.txt")
}

func (s *Server) handleGetSpoofIPs(c *gin.Context) {
	data, err := os.ReadFile(spoofIPFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusOK, gin.H{"content": "", "count": 0})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	content := strings.TrimSpace(string(data))
	count := 0
	if content != "" {
		count = len(strings.Split(content, "\n"))
	}

	c.JSON(http.StatusOK, gin.H{"content": content, "count": count})
}

func (s *Server) handleSetSpoofIPs(c *gin.Context) {
	var req struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	content := strings.TrimSpace(req.Content) + "\n"
	if err := os.WriteFile(spoofIPFilePath(), []byte(content), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	count := len(strings.Split(strings.TrimSpace(req.Content), "\n"))
	c.JSON(http.StatusOK, gin.H{"ok": true, "count": count})
}

func (s *Server) handleUploadSpoofIPs(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no file uploaded"})
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "read file: " + err.Error()})
		return
	}

	content := strings.TrimSpace(string(data)) + "\n"
	if err := os.WriteFile(spoofIPFilePath(), []byte(content), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	count := len(strings.Split(strings.TrimSpace(string(data)), "\n"))
	c.JSON(http.StatusOK, gin.H{"ok": true, "count": count, "content": strings.TrimSpace(string(data))})
}

func (s *Server) handleDownloadSpoofIPs(c *gin.Context) {
	data, err := os.ReadFile(spoofIPFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "no spoof IP file"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Disposition", "attachment; filename=spoof-ips.txt")
	c.Data(http.StatusOK, "text/plain", data)
}

// ── Helpers ──

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
