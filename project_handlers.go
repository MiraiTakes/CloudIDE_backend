package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

var projectMu sync.Mutex

// POST /project — создание нового проекта
func createProject(w http.ResponseWriter, r *http.Request) {
	// Достаём userID из JWT
	userID, err := getUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Читаем имя и языки из тела
	var payload struct {
		Name      string   `json:"name"`
		Languages []string `json:"languages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		log.Println("Ошибка декодирования запроса проекта:", err)
		return
	}
	if payload.Name == "" {
		http.Error(w, "Необходимо указать имя проекта", http.StatusBadRequest)
		return
	}

	// Проверяем, что такого проекта у пользователя нет
	var count int
	err = db.QueryRow(
		"SELECT COUNT(*) FROM projects WHERE name = ? AND user_id = ?",
		payload.Name, userID,
	).Scan(&count)
	if err != nil {
		http.Error(w, "Ошибка базы данных", http.StatusInternalServerError)
		log.Println("Ошибка проверки существования проекта:", err)
		return
	}
	if count > 0 {
		http.Error(w, "Проект с таким именем уже существует", http.StatusConflict)
		return
	}

	// Формируем данные проекта
	project := Project{
		ID:       uuid.NewString(),
		Name:     payload.Name,
		UserID:   userID,
		DockerID: "container_" + uuid.NewString(),
	}

	projectMu.Lock()
	defer projectMu.Unlock()

	success := false
	defer func() {
		if !success {
			log.Printf("Откат: удаляем контейнер %s", project.DockerID)
			exec.Command("docker", "rm", "-f", project.DockerID).Run()
		}
	}()

	// 1) Запускаем контейнер
	log.Printf("Запуск контейнера %s для проекта %s", project.DockerID, project.Name)
	if err := exec.Command(
		"docker", "run", "-dit",
		"--name", project.DockerID,
		"-e", "TERM=xterm",
		"ubuntu:latest", "bash",
	).Run(); err != nil {
		http.Error(w, "Не удалось создать контейнер", http.StatusInternalServerError)
		log.Println("docker run error:", err)
		return
	}

	// 2) Создаём структуры внутри контейнера
	paths := []string{ChangesDir, "/" + project.Name}
	for _, p := range paths {
		if err := exec.Command("docker", "exec", project.DockerID, "mkdir", "-p", p).Run(); err != nil {
			http.Error(w, "Ошибка создания директорий", http.StatusInternalServerError)
			log.Printf("mkdir -p %s error: %v", p, err)
			return
		}
	}

	// 3) Обновляем систему и ставим Git
	steps := [][]string{
		{"apt", "update"},
		{"apt", "upgrade", "-y"},
		{"apt", "install", "-y", "git"},
	}
	for _, cmdArgs := range steps {
    // формируем полный слайс аргументов: ["exec", project.DockerID, cmdArgs...]
    args := append([]string{"exec", project.DockerID}, cmdArgs...)
    if err := exec.Command("docker", args...).Run(); err != nil {
        http.Error(w, "Ошибка настройки контейнера", http.StatusInternalServerError)
        log.Printf("docker %v error: %v", args, err)
        return
    }
}

	// 4) Устанавливаем языки
	for _, lang := range payload.Languages {
		if err := installLanguage(project.DockerID, strings.ToLower(lang)); err != nil {
			http.Error(w, "Не удалось установить язык "+lang, http.StatusInternalServerError)
			log.Printf("installLanguage %s error: %v", lang, err)
			return
		}
	}

	// 5) Сохраняем в БД
	_, err = db.Exec(
		"INSERT INTO projects (id, user_id, name, docker_id) VALUES (?, ?, ?, ?)",
		project.ID, project.UserID, project.Name, project.DockerID,
	)
	if err != nil {
		http.Error(w, "Ошибка сохранения проекта", http.StatusInternalServerError)
		log.Println("DB INSERT error:", err)
		return
	}

	success = true
	w.WriteHeader(http.StatusCreated)
	log.Printf("Проект %s создан", project.Name)
}

// DELETE /project/{name} — удаление проекта
func deleteProject(w http.ResponseWriter, r *http.Request) {
	projectName := mux.Vars(r)["name"]

	userID, err := getUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Проверяем право владения
	if err := checkProjectOwnershipByName(projectName, userID); err != nil {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	// Берём docker_id
	dockerID, err := getDockerIDByProjectNameAndUser(projectName, userID)
	if err != nil {
		http.Error(w, "Проект не найден", http.StatusNotFound)
		return
	}

	// Останавливаем таймер автостанова и удаляем контейнер
	cancelStopTimer(dockerID)
	projectMu.Lock()
	err = exec.Command("docker", "rm", "-f", dockerID).Run()
	projectMu.Unlock()
	if err != nil {
		http.Error(w, "Не удалось удалить контейнер", http.StatusInternalServerError)
		return
	}

	// Удаляем запись из БД
	_, err = db.Exec("DELETE FROM projects WHERE name = ? AND user_id = ?", projectName, userID)
	if err != nil {
		http.Error(w, "Ошибка удаления из БД", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GET /projects — список проектов пользователя
func getUserProjects(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	rows, err := db.Query("SELECT id, name, docker_id, updated_at FROM projects WHERE user_id = ?", userID)
	if err != nil {
		http.Error(w, "Ошибка БД", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var projects []Project
	for rows.Next() {
		var p Project
		var ut sql.NullTime
		if err := rows.Scan(&p.ID, &p.Name, &p.DockerID, &ut); err != nil {
			http.Error(w, "Ошибка чтения данных", http.StatusInternalServerError)
			return
		}
		p.UserID = userID
		if ut.Valid {
			p.UpdatedAt = ut.Time.Format("2006-01-02 15:04:05")
		}
		projects = append(projects, p)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(projects)
}

// POST /project/clone — клонирование GitHub-репозитория
func cloneProject(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var payload struct{ RepoURL string `json:"repo_url"` }
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	// Проверяем токен GitHub
	var encryptedToken string
	if err := db.QueryRow("SELECT github_token FROM users WHERE id = ?", userID).
		Scan(&encryptedToken); err != nil || encryptedToken == "" {
		http.Error(w, "GitHub токен не найден", http.StatusForbidden)
		return
	}
	token, err := decryptToken(encryptedToken)
	if err != nil {
		http.Error(w, "Ошибка расшифровки токена", http.StatusInternalServerError)
		return
	}

	// Проверка и парсинг URL
	if !strings.HasPrefix(payload.RepoURL, "https://github.com/") {
		http.Error(w, "Поддерживаются только GitHub-репозитории", http.StatusBadRequest)
		return
	}
	path := strings.TrimSuffix(strings.TrimPrefix(payload.RepoURL, "https://github.com/"), ".git")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		http.Error(w, "Некорректный URL репозитория", http.StatusBadRequest)
		return
	}
	projName := parts[len(parts)-1]

	// Проверка дубликата
	var cnt int
	if err := db.QueryRow("SELECT COUNT(*) FROM projects WHERE name = ? AND user_id = ?", projName, userID).Scan(&cnt); err != nil {
		http.Error(w, "Ошибка БД", http.StatusInternalServerError)
		return
	}
	if cnt > 0 {
		http.Error(w, "Проект с таким именем уже существует", http.StatusConflict)
		return
	}

	// Запуск контейнера
	newContainer := "container_" + uuid.NewString()
	if err := exec.Command("docker", "run", "-d", "--name", newContainer, "ubuntu:latest", "tail", "-f", "/dev/null").Run(); err != nil {
		http.Error(w, "Не удалось запустить контейнер", http.StatusInternalServerError)
		return
	}

	// Установка Git и клонирование с GIT_ASKPASS
	script := fmt.Sprintf(`
apt update && apt install -y git
echo 'echo "%s"' > /tmp/askpass.sh
chmod +x /tmp/askpass.sh
export GIT_ASKPASS=/tmp/askpass.sh
git clone https://github.com/%s.git /%s
`, token, path, projName)

	cmd := exec.Command("docker", "exec", newContainer, "bash", "-c", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		exec.Command("docker", "rm", "-f", newContainer).Run()
		http.Error(w, "Ошибка клонирования: "+string(out), http.StatusInternalServerError)
		return
	}

	// Сохраняем в БД
	_, err = db.Exec("INSERT INTO projects (id, user_id, name, docker_id) VALUES (?, ?, ?, ?)",
		uuid.NewString(), userID, projName, newContainer,
	)
	if err != nil {
		exec.Command("docker", "rm", "-f", newContainer).Run()
		http.Error(w, "Ошибка БД", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
// GET /projects/stats — статистика проектов
func getUserProjectsStats(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var (
		total                        int
		firstAt, lastAt, updatedAt   time.Time
		firstName, lastName, updName sql.NullString
	)
	query := `
	SELECT
	  COUNT(*) AS total,
	  MIN(created_at) AS first_at,
	  MAX(created_at) AS last_at,
	  MAX(updated_at) AS updated_at,
	  (SELECT name FROM projects WHERE user_id = ? ORDER BY created_at LIMIT 1) AS first_name,
	  (SELECT name FROM projects WHERE user_id = ? ORDER BY created_at DESC LIMIT 1) AS last_name,
	  (SELECT name FROM projects WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1) AS upd_name
	FROM projects WHERE user_id = ?`
	if err := db.QueryRow(query, userID, userID, userID, userID).
		Scan(&total, &firstAt, &lastAt, &updatedAt, &firstName, &lastName, &updName); err != nil {
		http.Error(w, "Ошибка БД", http.StatusInternalServerError)
		return
	}

	resp := StatsResponse{
		Total: total,
		First: projectStat{Name: firstName.String, At: firstAt.Format("2006-01-02 15:04:05")},
		Last:  projectStat{Name: lastName.String,   At: lastAt.Format("2006-01-02 15:04:05")},
		Updated: projectStat{Name: updName.String,  At: updatedAt.Format("2006-01-02 15:04:05")},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}