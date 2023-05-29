package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
)

// User структура пользователя
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// JWTToken структура JWT токена
type JWTToken struct {
	Token string `json:"token"`
}

// JWTConfig структура конфигурации для JWT токена
type JWTConfig struct {
	SecretKey     string
	ExpiresInSecs int64
}

// APIResponse структура ответа для API
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
	Error   string      `json:"error,omitempty"`
}

// PGConfig структура конфигурации для Postgres
type PGConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	Database string
	SSLMode  string
}

var db *sql.DB
var jwtConfig JWTConfig

func main() {
	// Инициализируем конфигурацию Postgres
	pgConfig := PGConfig{
		Host:     "localhost",
		Port:     5432,
		Username: "postgres",
		Password: "password",
		Database: "jwt_demo",
		SSLMode:  "disable",
	}

	// Инициализируем конфигурацию JWT токена
	jwtConfig = JWTConfig{
		SecretKey:     "secret",
		ExpiresInSecs: 3600,
	}

	// Устанавливаем соединение с базой данных
	err := initDB(pgConfig)
	if err != nil {
		log.Fatalf("Ошибка при установлении соединения с базой данных: %s", err.Error())
	}
	defer db.Close()

	// Регистрируем хендлеры для роутов
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/secure", handleSecure)

	// Запускаем HTTP сервер
	log.Println("Запуск HTTP сервера...")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatalf("Ошибка при запуске HTTP сервера: %s", err.Error())
	}
}

// initDB устанавливает соединение с базой данных
func initDB(cfg PGConfig) error {
	var err error
	// dbinfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
	// 	cfg.Host, cfg.Port, cfg.Username, cfg.Password, cfg.Database, cfg.SSLMode)
	// db, err = sql.Open("postgres", dbinfo)
	db, err := sql.Open("postgres", "host=localhost port=5432 user=postgres dbname=postgres password=password sslmode=disable")
	if err != nil {
		return err
	}
	// Проверяем соединение с базой данных
	err = db.Ping()
	if err != nil {
		return err
	}

	// Создаем таблицу пользователей, если ее нет
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL);")
	if err != nil {
		return err
	}

	return nil
}

// type Credentials struct {
// 	Username string `json:"username"`
// 	Password string `json:"password"`
// }

// handleRegister обрабатывает запрос на регистрацию нового пользователя
func handleRegister(w http.ResponseWriter, r *http.Request) {
	// Получаем данные пользователя из тела запроса
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Проверяем, что данные получены
	if username == "" || password == "" {
		fmt.Println(username, password)
		writeError(w, "Не все данные переданы")
		return
	}

	// Проверяем, что пользователь с таким именем не существует
	user, err := getUserByUsername(username)
	if err != nil {
		writeError(w, "Ошибка при выполнении запроса к базе данных")
		return
	}
	if user != nil {
		writeError(w, "Пользователь с таким именем уже существует")
		return
	}

	// Хешируем пароль
	hashedPassword, err := hashPassword(password)
	if err != nil {
		writeError(w, "Ошибка при хешировании пароля")
		return
	}

	// Добавляем нового пользователя в базу данных
	_, err = db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", username, hashedPassword)
	if err != nil {
		writeError(w, "Ошибка при выполнении запроса к базе данных")
		return
	}

	writeSuccess(w, "Регистрация прошла успешно")
}

// handleLogin обрабатывает запрос на вход пользователя
func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Получаем данные пользователя из тела запроса
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Проверяем, что данные получены
	if username == "" || password == "" {
		writeError(w, "Не все данные переданы")
		return
	}

	// Получаем пользователя из базы данных
	user, err := getUserByUsername(username)
	if err != nil {
		writeError(w, "Ошибка при выполнении запроса к базе данных")
		return
	}
	if user == nil {
		writeError(w, "Неверные имя пользователя или пароль")
		return
	}

	// Проверяем пароль
	err = checkPassword(user.Password, password)
	if err != nil {
		writeError(w, "Неверные имя пользователя или пароль")
		return
	}

	// Генерируем JWT токен
	token, err := generateJWTToken(user.ID)
	if err != nil {
		writeError(w, "Ошибка при генерации токена")
		return
	}

	// Отдаем токен пользователю
	writeData(w, JWTToken{Token: token})
}

// handleSecure обрабатывает защищенный запрос
func handleSecure(w http.ResponseWriter, r *http.Request) {
	// Получаем JWT токен из заголовка Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		writeError(w, "Токен не указан")
		return
	}
	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || authHeaderParts[0] != "Bearer" {
		writeError(w, "Неверный формат токена")
		return
	}
	tokenString := authHeaderParts[1]

	// Проверяем JWT токен
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Неверный метод подписи токена: %v", token.Header["alg"])
		}
		return []byte(jwtConfig.SecretKey), nil
	})
	if err != nil {
		writeError(w, "Ошибка при проверке токена")
		return
	}
	if !token.Valid {
		writeError(w, "Невалидный токен")
		return
	}

	userID, ok := token.Claims.(jwt.MapClaims)["user_id"].(float64)
	if !ok {
		writeError(w, "Ошибка при чтении идентификатора пользователя")
		return
	}

	// Получаем пользователя из базы данных
	user, err := getUserByID(int(userID))
	if err != nil {
		writeError(w, "Ошибка при выполнении запроса к базе данных")
		return
	}
	if user == nil {
		writeError(w, "Ошибка при чтении пользователя из базы данных")
		return
	}

	writeSuccess(w, fmt.Sprintf("Защищенный запрос выполнен для пользователя с ID=%d", user.ID))
}

// getUserByUsername получает пользователя по его имени в базе данных
func getUserByUsername(username string) (*User, error) {
	var user User
	row := db.QueryRow("SELECT id, username, password FROM users WHERE username=$1", username)
	err := row.Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// getUserByID получает пользователя по его ID в базе данных
func getUserByID(id int) (*User, error) {
	var user User
	row := db.QueryRow("SELECT id, username, password FROM users WHERE id=$1", id)
	err := row.Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// hashPassword хеширует пароль
func hashPassword(password string) (string, error) {
	// В реальном приложении стоит использовать более сложный алгоритм хеширования, например bcrypt
	return password, nil
}

// checkPassword проверяет пароль на соотвествие хешу пароля в базе данных
func checkPassword(hashedPassword, password string) error {
	// В реальном приложении стоит использовать более сложный алгоритм хеширования, например bcrypt
	if hashedPassword == password {
		return nil
	}
	return fmt.Errorf("неверный пароль")
}

// generateJWTToken генерирует JWT токен для пользователя с указанным ID
func generateJWTToken(userID int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Duration(jwtConfig.ExpiresInSecs) * time.Second).Unix(),
	})
	return token.SignedString([]byte(jwtConfig.SecretKey))
}

// writeSuccess записывает успешный ответ API в HTTP ResponseWriter в формате JSON
func writeSuccess(w http.ResponseWriter, data interface{}) {
	response := APIResponse{
		Success: true,
		Data:    data,
	}
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Ошибка при сериализации успешного ответа API в JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBytes)
}

// writeData записывает данные в HTTP ResponseWriter в формате JSON
func writeData(w http.ResponseWriter, data interface{}) {
	response := APIResponse{
		Success: true,
		Data:    data,
	}
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Ошибка при сериализации данных в JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBytes)
}

// writeError записывает ошибку в HTTP ResponseWriter в формате JSON
func writeError(w http.ResponseWriter, errorMessage string) {
	response := APIResponse{
		Success: false,
		Error:   errorMessage,
	}
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Ошибка при сериализации ошибки в JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	w.Write(jsonBytes)
}
