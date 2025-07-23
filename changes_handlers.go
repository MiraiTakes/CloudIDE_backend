package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"

	"github.com/gorilla/mux"
)

// POST /project/{name}/changed-files
func postChangedFilesHandler(w http.ResponseWriter, r *http.Request) {
	projectName := mux.Vars(r)["name"]

	// 1) Аутентификация
	userID, err := getUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	// 2) Проверяем право владения проектом
	if err := checkProjectOwnership(projectName, userID); err != nil {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}
	// 3) Получаем docker_id по проекту и пользователю
	dockerID, err := getDockerIDByProjectNameAndUser(projectName, userID)
	if err != nil {
		http.Error(w, "Проект не найден", http.StatusNotFound)
		return
	}

	// 4) Читаем список файлов из тела
	var payload ChangedFilesPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Неверный формат JSON", http.StatusBadRequest)
		return
	}

	// 5) Сериализуем и записываем в контейнер
	data, _ := json.MarshalIndent(payload, "", "  ")
	inContainerPath := fmt.Sprintf("%s/%s__%s.json", ChangesDir, projectName, userID)
	cmd := exec.Command(
		"docker", "exec", "-i", dockerID,
		"bash", "-c", fmt.Sprintf("mkdir -p %s && cat > %s", ChangesDir, inContainerPath),
	)
	cmd.Stdin = bytes.NewReader(data)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Ошибка записи в контейнер %s: %v, output=%s", dockerID, err, out)
		http.Error(w, "Не удалось сохранить изменения", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GET /project/{name}/changed-files — получить список изменений
func getChangedFilesHandler(w http.ResponseWriter, r *http.Request) {
	projectName := mux.Vars(r)["name"]

	// 1) Аутентификация
	userID, err := getUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	// 2) Проверяем право владения проектом
	if err := checkProjectOwnership(projectName, userID); err != nil {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}
	// 3) Получаем docker_id по проекту и пользователю
	dockerID, err := getDockerIDByProjectNameAndUser(projectName, userID)
	if err != nil {
		http.Error(w, "Проект не найден", http.StatusNotFound)
		return
	}

	// 4) Читаем файл изменений внутри контейнера
	inContainerPath := fmt.Sprintf("%s/%s__%s.json", ChangesDir, projectName, userID)
	cmd := exec.Command("docker", "exec", dockerID, "cat", inContainerPath)
	output, err := cmd.Output()
	if err != nil {
		// Если файла нет — возвращаем пустой список
		if exitErr, ok := err.(*exec.ExitError); ok && bytes.Contains(exitErr.Stderr, []byte("No such file")) {
			json.NewEncoder(w).Encode(ChangedFilesPayload{Files: []string{}})
			return
		}
		log.Printf("Ошибка чтения изменений из контейнера %s: %v", dockerID, err)
		http.Error(w, "Не удалось прочитать изменения", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(output)
}