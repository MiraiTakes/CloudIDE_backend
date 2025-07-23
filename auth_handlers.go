package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"math/rand"
	"os"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	gh "golang.org/x/oauth2/github"
	"cloudide/mailer"
)

// Настройки OAuth2 для GitHub (CLIENT_ID/SECRET)
var githubOAuthConfig *oauth2.Config

func init() {
    clientID := os.Getenv("GITHUB_CLIENT_ID")
    clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")
    if clientID == "" || clientSecret == "" {
        log.Fatal("Environment variables GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET not set")
    }

    githubOAuthConfig = &oauth2.Config{
        ClientID:     clientID,
        ClientSecret: clientSecret,
        Endpoint:     gh.Endpoint,
        RedirectURL:  os.Getenv("GITHUB_OAUTH_REDIRECT_URL"),
        Scopes:       []string{"repo", "user:email"},
    }
}

var oauthStates = make(map[string]string)

func verifyCode(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Email string `json:"email"`
        Code  string `json:"code"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Неверный формат", http.StatusBadRequest)
        return
    }

    var used bool
    var exp time.Time
    err := db.QueryRow(
        "SELECT used, expires FROM email_codes WHERE email = ? AND code = ?",
        req.Email, req.Code,
    ).Scan(&used, &exp)
    if err != nil || used || time.Now().After(exp) {
        http.Error(w, "invalid", http.StatusUnauthorized)
        return
    }

    // Помечаем код как использованный
    _, _ = db.Exec(
        "UPDATE email_codes SET used = TRUE WHERE email = ? AND code = ?",
        req.Email, req.Code,
    )

    w.WriteHeader(http.StatusOK)
}

// Регистрация пользователя
func registerUser(w http.ResponseWriter, r *http.Request) {
    // 1) Принять и валидировать входящие данные
    var u User
    if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
        http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
        return
    }
    if u.Username == "" || u.Email == "" || u.Password == "" {
        http.Error(w, "Все поля обязательны", http.StatusBadRequest)
        return
    }

    // 2) Проверяем, есть ли уже запись с таким email
    var existingID string
    var emailVerified bool
    err := db.QueryRow(
        "SELECT id, email_verified FROM users WHERE email = ?",
        u.Email,
    ).Scan(&existingID, &emailVerified)

    switch {
    case err == sql.ErrNoRows:
        // e-mail ещё не встречался — идём дальше создавать
    case err != nil:
        log.Println("DB error checking email:", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    default:
        // нашли запись
        if !emailVerified {
            // пользователь уже регистрировался, но не подтвердил почту
            sendNewVerification(existingID, u.Email, w)
            return
        }
        // если email_verified == true — блокируем повторную регистрацию
        http.Error(w, "Email уже занят", http.StatusConflict)
        return
    }

    // 3) Хэшируем пароль
    hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
    if err != nil {
        log.Println("bcrypt error:", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    // 4) Вставляем новую учётку (email_verified по умолчанию FALSE)
    u.ID = uuid.NewString()
    _, err = db.Exec(
        `INSERT INTO users
           (id, username, email, password, created_at, email_verified)
         VALUES (?, ?, ?, ?, NOW(), FALSE)`,
        u.ID, u.Username, u.Email, string(hash),
    )
    if err != nil {
        log.Println("DB insert user error:", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    // 5) Генерируем и отправляем код в helper-функции
    sendNewVerification(u.ID, u.Email, w)
}

func sendNewVerification(userID, email string, w http.ResponseWriter) {
    // Удаляем старые коды (если были)
    _, _ = db.Exec("DELETE FROM email_codes WHERE user_id = ?", userID)

    // Генерируем новый 6-значный код
    code := fmt.Sprintf("%06d", rand.Intn(1_000_000))
    expires := time.Now().Add(10 * time.Minute)

    // Сохраняем код
    if _, err := db.Exec(
        `INSERT INTO email_codes
           (user_id, email, code, expires, used)
         VALUES (?, ?, ?, ?, FALSE)`,
        userID, email, code, expires,
    ); err != nil {
        log.Println("DB insert code error:", err)
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    // Отправляем код
    if err := mailer.SendVerificationCodeResend(email, code); err != nil {
        log.Println("Resend send error:", err)
        http.Error(w, "Не удалось отправить код подтверждения", http.StatusInternalServerError)
        return
    }

    // HTTP 202 — «Код выслан повторно»
    w.WriteHeader(http.StatusAccepted)
    w.Write([]byte("Код подтверждения отправлен"))
}

// Логин пользователя (возвращает JWT)
func loginUser(w http.ResponseWriter, r *http.Request) {
	var reqUser User
	if err := json.NewDecoder(r.Body).Decode(&reqUser); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	var user User
	err := db.QueryRow("SELECT id, password FROM users WHERE email = ?", reqUser.Email).Scan(&user.ID, &user.Password)
	if err != nil {
		http.Error(w, "Пользователь не найден", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(reqUser.Password)); err != nil {
		http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Ошибка генерации токена", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// GET /auth/github/login
func githubLogin(w http.ResponseWriter, r *http.Request) {
	tokenStr := ""
	authHeader := r.Header.Get("Authorization")
	if parts := strings.Split(authHeader, " "); len(parts) == 2 && parts[0] == "Bearer" {
		tokenStr = parts[1]
	}
	if tokenStr == "" {
		tokenStr = r.URL.Query().Get("token")
	}
	if tokenStr == "" {
		http.Error(w, "Отсутствует токен", http.StatusUnauthorized)
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Неверный или просроченный токен", http.StatusUnauthorized)
		return
	}

	userID := claims.UserID
	state := uuid.New().String()

	oauthStates[state] = userID
	url := githubOAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusFound)
}

// GET /auth/github/callback
func githubCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	userID, ok := oauthStates[state]
	if !ok {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	delete(oauthStates, state)

	token, err := githubOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	client := githubOAuthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		http.Error(w, "Failed to fetch GitHub user", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var ghUser struct{ Login string `json:"login"` }
	if err := json.NewDecoder(resp.Body).Decode(&ghUser); err != nil {
		http.Error(w, "Failed to parse GitHub user", http.StatusInternalServerError)
		return
	}

	// Шифруем токен
	encrypted, err := encryptToken(token.AccessToken)
	if err != nil {
		http.Error(w, "Failed to encrypt GitHub token", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(
		"UPDATE users SET github_token = ?, github_login = ? WHERE id = ?",
		encrypted, ghUser.Login, userID,
	)
	if err != nil {
		http.Error(w, "Failed to store GitHub info", http.StatusInternalServerError)
		return
	}


	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	jwtToken, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtKey)
	redirect := fmt.Sprintf("androidide://auth/success?token=%s", jwtToken)
	http.Redirect(w, r, redirect, http.StatusFound)
}

// GET /users/{id}
func getUserProfile(w http.ResponseWriter, r *http.Request) {
    jwtUserID, err := getUserID(r)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }
    pathID := mux.Vars(r)["id"]
    if pathID != jwtUserID {
        http.Error(w, "Доступ запрещён", http.StatusForbidden)
        return
    }

    var user User
    var ghLogin, ghToken sql.NullString
    err = db.QueryRow(
        "SELECT id, username, email, github_login, github_token FROM users WHERE id = ?",
        jwtUserID,
    ).Scan(&user.ID, &user.Username, &user.Email, &ghLogin, &ghToken)
    if err == sql.ErrNoRows {
        http.Error(w, "Пользователь не найден", http.StatusNotFound)
        return
    } else if err != nil {
        log.Printf("DB error fetching user %s: %v", jwtUserID, err)
        http.Error(w, "Внутренняя ошибка сервера", http.StatusInternalServerError)
        return
    }

    if ghLogin.Valid {
        user.GitHubLogin = &ghLogin.String
    }
    if ghToken.Valid {
        decrypted, err := decryptToken(ghToken.String)
        if err != nil {
            log.Printf("Failed to decrypt GitHub token for user %s: %v", jwtUserID, err)
            http.Error(w, "Internal error", http.StatusInternalServerError)
            return
        }
        user.GitHubToken = decrypted
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(user)
}