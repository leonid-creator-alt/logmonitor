// backend/main.go
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/pquerna/otp/totp"
)

// ---------- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ----------
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var clients = make(map[*websocket.Conn]bool)
var clientsMutex = sync.Mutex{}
var broadcast = make(chan string, 500)

var jwtSecret = []byte("logmonitor-secret-key-2024")

// ---------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ РАБОТЫ С БД ----------

func callDBModule(method, endpoint string, body interface{}) (map[string]interface{}, error) {
	var reqBody *bytes.Reader
	if body != nil {
		jsonData, _ := json.Marshal(body)
		reqBody = bytes.NewReader(jsonData)
	} else {
		reqBody = bytes.NewReader([]byte{})
	}

	req, _ := http.NewRequest(method, "http://localhost:8081"+endpoint, reqBody)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// Проверка пароля через DB модуль
func verifyPasswordViaDB(username, password string) (bool, bool, error) {
	loginData := map[string]string{
		"username": username,
		"password": password,
	}

	result, err := callDBModule("POST", "/api/user/verify-password", loginData)
	if err != nil {
		return false, false, err
	}

	valid, ok := result["valid"].(bool)
	if !ok {
		return false, false, nil
	}

	twofaEnabled, _ := result["twofa_enabled"].(bool)
	return valid, twofaEnabled, nil
}

// Получение 2FA секрета пользователя из БД
func getUser2FASecret(username string) (string, error) {
	result, err := callDBModule("GET", "/api/user/"+username+"/twofa-secret", nil)
	if err != nil {
		return "", err
	}

	secret, ok := result["twofa_secret"].(string)
	if !ok {
		return "", fmt.Errorf("no 2fa secret for user")
	}
	return secret, nil
}

// Сохранение 2FA секрета в БД
func saveUser2FASecret(username, secret string) error {
	data := map[string]interface{}{
		"username": username,
		"secret":   secret,
		"enabled":  true,
	}
	_, err := callDBModule("POST", "/api/user/setup-2fa", data)
	return err
}

// ---------- ФУНКЦИЯ ЗАПУСКА PYTHON-ПАРСЕРА ----------
func parseLogWithPython(rawLog string) (map[string]interface{}, error) {
	cmd := exec.Command("python", "../parser_module/parser.py")
	cmd.Stdin = strings.NewReader(rawLog)

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// ---------- ЧТЕНИЕ ЛОГОВ WINDOWS ----------
func readWindowsLogs() {
	logs := []string{"System", "Application", "Security"}

	for {
		for _, logName := range logs {
			cmd := exec.Command("wevtutil", "qe", "/rd:true", "/c:3", "/format:text", logName)
			output, err := cmd.Output()
			if err != nil {
				log.Printf("Ошибка чтения %s: %v", logName, err)
				continue
			}

			rawEvents := strings.Split(string(output), "Event[")

			for _, rawEvent := range rawEvents {
				if strings.TrimSpace(rawEvent) == "" {
					continue
				}
				fullEvent := "Event[" + rawEvent

				go func(event string) {
					parsed, err := parseLogWithPython(event)
					if err != nil {
						log.Printf("Ошибка парсинга: %v", err)
						return
					}

					jsonMsg, _ := json.Marshal(parsed)
					broadcast <- string(jsonMsg)

					if critical, ok := parsed["is_critical"].(bool); ok && critical {
						sendToDBModule(parsed)
					}
				}(fullEvent)
			}
		}
		time.Sleep(3 * time.Second)
	}
}

// ---------- ОТПРАВКА В DB МОДУЛЬ ----------
func sendToDBModule(parsed map[string]interface{}) {
	data := map[string]interface{}{
		"source":      parsed["source"],
		"message":     parsed["message"],
		"level":       parsed["level"],
		"log_name":    parsed["log_name"],
		"event_id":    parsed["event_id"],
		"is_error":    parsed["is_error"],
		"is_critical": parsed["is_critical"],
	}

	go func() {
		_, err := callDBModule("POST", "/api/alert", data)
		if err != nil {
			log.Printf("Ошибка отправки в DB модуль: %v", err)
		}
	}()
}

// ---------- WEBSOCKET ----------
func handleWebSocket(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket error: %v", err)
		return
	}
	defer conn.Close()

	clientsMutex.Lock()
	clients[conn] = true
	clientsMutex.Unlock()

	conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"connected"}`))

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}

	clientsMutex.Lock()
	delete(clients, conn)
	clientsMutex.Unlock()
}

func broadcastToClients() {
	for {
		msg := <-broadcast
		clientsMutex.Lock()
		for client := range clients {
			if err := client.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
				client.Close()
				delete(clients, client)
			}
		}
		clientsMutex.Unlock()
	}
}

// ---------- АВТОРИЗАЦИЯ (РЕАЛЬНАЯ, ЧЕРЕЗ БД) ----------
type LoginRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	TwoFACode string `json:"twofa_code,omitempty"`
}

type LoginResponse struct {
	Token      string `json:"token,omitempty"`
	Require2FA bool   `json:"require_2fa"`
}

// Настройка 2FA (генерация секрета и QR)
type Setup2FAResponse struct {
	Secret string `json:"secret"`
	QRCode string `json:"qr_code"`
}

func handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Проверяем пароль через БД
	valid, twofaEnabled, err := verifyPasswordViaDB(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Если 2FA включена и код не передан — требуем код
	if twofaEnabled && req.TwoFACode == "" {
		c.JSON(http.StatusOK, LoginResponse{Require2FA: true})
		return
	}

	// Если 2FA включена — проверяем код
	if twofaEnabled {
		secret, err := getUser2FASecret(req.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "2FA not configured"})
			return
		}

		valid := totp.Validate(req.TwoFACode, secret)
		if !valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid 2FA code"})
			return
		}
	}

	// Генерируем JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": req.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, _ := token.SignedString(jwtSecret)

	c.JSON(http.StatusOK, LoginResponse{Token: tokenString})
}

// Эндпоинт для настройки 2FA (генерация секрета)
func handleSetup2FA(c *gin.Context) {
	username := c.Query("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username required"})
		return
	}

	// Генерируем новый секрет
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "LogMonitor",
		AccountName: username,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Cannot generate 2FA secret"})
		return
	}

	// Сохраняем секрет в БД
	if err := saveUser2FASecret(username, key.Secret()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Cannot save 2FA secret"})
		return
	}

	// Возвращаем секрет и QR-код
	qrImage, err := key.Image(200, 200)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Cannot generate QR code"})
		return
	}

	c.JSON(http.StatusOK, Setup2FAResponse{
		Secret: key.Secret(),
		QRCode: "data:image/png;base64," + base64QRCode(qrImage),
	})
}

// Вспомогательная функция для преобразования QR-кода в base64
func base64QRCode(img image.Image) string {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// Middleware для проверки JWT
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// ---------- MAIN ----------
func main() {
	go readWindowsLogs()
	go broadcastToClients()

	r := gin.Default()

	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	// Публичные маршруты
	r.POST("/api/login", handleLogin)
	r.GET("/api/ws", handleWebSocket)
	r.GET("/api/setup-2fa", handleSetup2FA)

	// Защищённые маршруты
	authorized := r.Group("/api")
	authorized.Use(authMiddleware())
	{
		authorized.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})
	}

	log.Println("🚀 Go backend on http://localhost:8080")
	r.Run(":8080")
}
