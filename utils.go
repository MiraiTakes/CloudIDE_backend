package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"path"
	"strings"
	"time"
	"database/sql"

	"github.com/golang-jwt/jwt/v4"
)

type contextKey string

const userIDKey = contextKey("userID")

// JWT-мидлвар для защиты эндпоинтов
func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := ""
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) == 2 && parts[0] == "Bearer" {
				tokenStr = parts[1]
			}
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

		ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Получить userID из контекста после JWT-мидлвара
func getUserID(r *http.Request) (string, error) {
	userID, ok := r.Context().Value(userIDKey).(string)
	if !ok || userID == "" {
		return "", errors.New("пользователь не авторизован")
	}
	return userID, nil
}

func checkProjectOwnershipByName(projectName, userID string) error {
    var ownerID string
    err := db.QueryRow(
        "SELECT user_id FROM projects WHERE name = ? AND user_id = ?", 
        projectName, userID,
    ).Scan(&ownerID)
    
    if err != nil {
        if err == sql.ErrNoRows {
            return errors.New("проект не найден")
        }
        return err
    }
    return nil
}

// Получение docker_id по имени проекта и user_id
func getDockerIDByProjectNameAndUser(projectName, userID string) (string, error) {
    var dockerID string
    err := db.QueryRow(
        "SELECT docker_id FROM projects WHERE name = ? AND user_id = ?", 
        projectName, userID,
    ).Scan(&dockerID)
    if err != nil {
        return "", err
    }
    return dockerID, nil
}

// Проверка владения проектом: сравнивает user_id из БД с переданным
func checkProjectOwnership(projectName, userID string) error {
    var ownerID string
    err := db.QueryRow(
        "SELECT user_id FROM projects WHERE name = ? AND user_id = ?", 
        projectName, userID,
    ).Scan(&ownerID)
    if err == sql.ErrNoRows {
        return errors.New("проект не найден или доступ запрещён")
    }
    return err
}

// Получение docker_id проекта по его имени
func getDockerIDByProjectName(projectName, userID string) (string, error) {
    var dockerID string
    err := db.QueryRow(
        "SELECT docker_id FROM projects WHERE name = ? AND user_id = ?", 
        projectName, userID,
    ).Scan(&dockerID)
    return dockerID, err
}
// Безопасное формирование пути внутри контейнера: убирает “../” и гарантирует, что остаётся в каталоге проекта
func sanitizeContainerPath(projectName, userPath string) (string, error) {
	// Заменяем обратные слэши на прямые, убираем ведущие слэши
	cleaned := strings.TrimPrefix(strings.ReplaceAll(userPath, "\\", "/"), "/")
	full := "/" + projectName + "/" + cleaned
	cleanFull := path.Clean(full)
	if !strings.HasPrefix(cleanFull, "/"+projectName+"/") {
		return "", errors.New("некорректный путь")
	}
	return cleanFull, nil
}

// Обновление времени выхода пользователя из проекта (updated_at)
func updateProjectExitTime(projectName string) {
	now := time.Now()
	_, err := db.Exec("UPDATE projects SET updated_at = ? WHERE name = ?", now, projectName)
	if err != nil {
		log.Printf("Ошибка обновления updated_at для проекта %s: %v", projectName, err)
	} else {
		log.Printf("Время выхода пользователя обновлено для проекта %s: %v", projectName, now)
	}
}