package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"

	"github.com/gorilla/mux"
)

// DELETE /project/{name}/file — удалить файл или папку
// Параметр filename передаётся в query, например: ?filename=path/to/file.txt
func deleteFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectName := vars["name"]

	// 1) Проверяем авторизацию
	userID, err := getUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	// 2) Убеждаемся, что проект принадлежит текущему пользователю
	if err := checkProjectOwnership(projectName, userID); err != nil {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}
	// 3) Получаем docker_id по имени + user_id
	dockerID, err := getDockerIDByProjectNameAndUser(projectName, userID)
	if err != nil {
		http.Error(w, "Проект не найден", http.StatusNotFound)
		return
	}
	// 4) Считываем имя файла из запроса
	fileName := r.URL.Query().Get("filename")
	if fileName == "" {
		http.Error(w, "Параметр filename обязателен", http.StatusBadRequest)
		return
	}
	// 5) Проверяем, что контейнер запущен
	cmdCheck := exec.Command("docker", "ps", "-q", "-f", "name="+dockerID)
	outCheck, err := cmdCheck.Output()
	if err != nil || len(outCheck) == 0 {
		http.Error(w, "Контейнер не найден", http.StatusNotFound)
		return
	}
	containerID := strings.TrimSpace(string(outCheck))
	// 6) Формируем безопасный путь внутри контейнера
	safePath, err := sanitizeContainerPath(projectName, fileName)
	if err != nil {
		http.Error(w, "Некорректный путь", http.StatusBadRequest)
		return
	}
	// 7) Удаляем файл/папку
	cmd := exec.Command("docker", "exec", containerID, "bash", "-c", fmt.Sprintf("rm -rf %s", safePath))
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Ошибка удаления в контейнере %s: %v, output=%s", containerID, err, out)
		http.Error(w, "Ошибка удаления: "+string(out), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Удалено"))
}

// POST /project/{name}/folder — создать папку
func createFolder(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectName := vars["name"]

	userID, err := getUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := checkProjectOwnership(projectName, userID); err != nil {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}
	dockerID, err := getDockerIDByProjectNameAndUser(projectName, userID)
	if err != nil {
		http.Error(w, "Проект не найден", http.StatusNotFound)
		return
	}

	var payload struct {
		FolderPath string `json:"folderPath"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	if payload.FolderPath == "" {
		http.Error(w, "Путь папки не указан", http.StatusBadRequest)
		return
	}
	fullPath, err := sanitizeContainerPath(projectName, payload.FolderPath)
	if err != nil {
		http.Error(w, "Некорректный путь", http.StatusBadRequest)
		return
	}

	cmd := exec.Command("docker", "exec", dockerID, "mkdir", "-p", fullPath)
	if err := cmd.Run(); err != nil {
		log.Printf("Ошибка создания папки %s: %v", fullPath, err)
		http.Error(w, "Не удалось создать папку: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Папка создана"))
}

// POST /project/{name}/move — переместить файл или папку
func moveFileOrFolder(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectName := vars["name"]

	userID, err := getUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := checkProjectOwnership(projectName, userID); err != nil {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}
	dockerID, err := getDockerIDByProjectNameAndUser(projectName, userID)
	if err != nil {
		http.Error(w, "Проект не найден", http.StatusNotFound)
		return
	}

	var payload struct {
		OldPath string `json:"oldPath"`
		NewPath string `json:"newPath"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	if payload.OldPath == "" || payload.NewPath == "" {
		http.Error(w, "Укажите старый и новый пути", http.StatusBadRequest)
		return
	}
	oldFull, err := sanitizeContainerPath(projectName, payload.OldPath)
	if err != nil {
		http.Error(w, "Некорректный старый путь", http.StatusBadRequest)
		return
	}
	newFull, err := sanitizeContainerPath(projectName, payload.NewPath)
	if err != nil {
		http.Error(w, "Некорректный новый путь", http.StatusBadRequest)
		return
	}

	cmd := exec.Command("docker", "exec", dockerID, "mv", oldFull, newFull)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Ошибка перемещения %s -> %s: %v, output=%s", oldFull, newFull, err, out)
		http.Error(w, "Ошибка перемещения: "+string(out), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Файл/папка перемещены"))
}

// GET /project/{name}/files — список файлов и папок
func listFiles(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectName := vars["name"]

	userID, err := getUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := checkProjectOwnership(projectName, userID); err != nil {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}
	dockerID, err := getDockerIDByProjectNameAndUser(projectName, userID)
	if err != nil {
		http.Error(w, "Проект не найден", http.StatusNotFound)
		return
	}

	// Проверяем, что контейнер запущен
	cmdCheck := exec.Command("docker", "ps", "-q", "-f", "name="+dockerID)
	outCheck, err := cmdCheck.Output()
	if err != nil || len(outCheck) == 0 {
		http.Error(w, "Контейнер не найден", http.StatusNotFound)
		return
	}
	containerID := strings.TrimSpace(string(outCheck))

	cmd := exec.Command("docker", "exec", containerID, "bash", "-c",
		"find /"+projectName+" -mindepth 1 -exec bash -c 'if [ -d \"{}\" ]; then echo \"{}\\/\"; else echo \"{}\"; fi' \\;")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Ошибка получения списка файлов: %v", err)
		http.Error(w, "Ошибка получения списка файлов", http.StatusInternalServerError)
		return
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var items []string
	prefix := "/" + projectName + "/"
	for _, p := range lines {
		if strings.HasPrefix(p, prefix) {
			items = append(items, strings.TrimPrefix(p, prefix))
		} else {
			items = append(items, p)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(items)
}

// POST /project/{name}/file — сохранить содержимое файла
func saveFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectName := vars["name"]

	userID, err := getUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := checkProjectOwnership(projectName, userID); err != nil {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}
	dockerID, err := getDockerIDByProjectNameAndUser(projectName, userID)
	if err != nil {
		http.Error(w, "Проект не найден", http.StatusNotFound)
		return
	}

	// Проверяем контейнер
	cmdCheck := exec.Command("docker", "ps", "-q", "-f", "name="+dockerID)
	outCheck, err := cmdCheck.Output()
	if err != nil || len(outCheck) == 0 {
		http.Error(w, "Контейнер не найден", http.StatusNotFound)
		return
	}
	containerID := strings.TrimSpace(string(outCheck))

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Ошибка чтения тела запроса", http.StatusBadRequest)
		log.Println("Ошибка чтения тела:", err)
		return
	}

	var payload struct {
		FileName string `json:"filename"`
		Content  string `json:"content"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "Неверный JSON", http.StatusBadRequest)
		log.Println("Ошибка декодирования JSON:", err)
		return
	}
	if payload.FileName == "" {
		http.Error(w, "Имя файла не указано", http.StatusBadRequest)
		return
	}
	safePath, err := sanitizeContainerPath(projectName, payload.FileName)
	if err != nil {
		http.Error(w, "Некорректный путь", http.StatusBadRequest)
		return
	}

	cmd := exec.Command("docker", "exec", "-i", containerID, "bash", "-c", fmt.Sprintf("cat > %s", safePath))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		http.Error(w, "Ошибка создания потока ввода", http.StatusInternalServerError)
		log.Println("Stdin pipe error:", err)
		return
	}
	if err := cmd.Start(); err != nil {
		http.Error(w, "Ошибка запуска команды", http.StatusInternalServerError)
		log.Println("Cmd start error:", err)
		return
	}
	if _, err := io.WriteString(stdin, payload.Content); err != nil {
		http.Error(w, "Ошибка записи в файл", http.StatusInternalServerError)
		log.Println("WriteString error:", err)
		stdin.Close()
		return
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		http.Error(w, "Ошибка сохранения файла", http.StatusInternalServerError)
		log.Println("Cmd wait error:", err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// GET /project/{name}/file?filename=...
func getFileContent(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectName := vars["name"]

	userID, err := getUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := checkProjectOwnership(projectName, userID); err != nil {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}
	dockerID, err := getDockerIDByProjectNameAndUser(projectName, userID)
	if err != nil {
		http.Error(w, "Проект не найден", http.StatusNotFound)
		return
	}

	cmdCheck := exec.Command("docker", "ps", "-q", "-f", "name="+dockerID)
	outCheck, err := cmdCheck.Output()
	if err != nil || len(outCheck) == 0 {
		http.Error(w, "Контейнер не найден", http.StatusNotFound)
		return
	}
	containerID := strings.TrimSpace(string(outCheck))

	fileName := r.URL.Query().Get("filename")
	if fileName == "" {
		http.Error(w, "Параметр filename обязателен", http.StatusBadRequest)
		return
	}
	safePath, err := sanitizeContainerPath(projectName, fileName)
	if err != nil {
		http.Error(w, "Некорректный путь", http.StatusBadRequest)
		return
	}

	cmd := exec.Command("docker", "exec", containerID, "cat", safePath)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Ошибка получения содержимого", http.StatusInternalServerError)
		log.Println("Read file error:", err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(output)
}

// POST /project/{name}/run — запуск файла
func runFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectName := vars["name"]

	userID, err := getUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := checkProjectOwnership(projectName, userID); err != nil {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}
	dockerID, err := getDockerIDByProjectNameAndUser(projectName, userID)
	if err != nil {
		http.Error(w, "Проект не найден", http.StatusNotFound)
		return
	}

	var payload struct{ FileName string `json:"filename"` }
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	if payload.FileName == "" {
		http.Error(w, "Параметр filename обязателен", http.StatusBadRequest)
		return
	}
	safePath, err := sanitizeContainerPath(projectName, payload.FileName)
	if err != nil {
		http.Error(w, "Некорректный путь", http.StatusBadRequest)
		return
	}

	// проверяем контейнер
	cmdCheck := exec.Command("docker", "ps", "-q", "-f", "name="+dockerID)
	outCheck, err := cmdCheck.Output()
	if err != nil || len(outCheck) == 0 {
		http.Error(w, "Контейнер не найден", http.StatusNotFound)
		return
	}
	containerID := strings.TrimSpace(string(outCheck))

	// выбираем команду в зависимости от расширения
	var runCmd *exec.Cmd
	switch {
	case strings.HasSuffix(payload.FileName, ".py"):
		runCmd = exec.Command("docker", "exec", containerID, "python", safePath)
	case strings.HasSuffix(payload.FileName, ".js"):
		runCmd = exec.Command("docker", "exec", containerID, "node", safePath)
	case strings.HasSuffix(payload.FileName, ".dart"):
		runCmd = exec.Command("docker", "exec", containerID, "dart", safePath)
	case strings.HasSuffix(payload.FileName, ".go"):
		runCmd = exec.Command("docker", "exec", containerID, "go", "run", safePath)
	case strings.HasSuffix(payload.FileName, ".php"):
		runCmd = exec.Command("docker", "exec", containerID, "php", safePath)
	case strings.HasSuffix(payload.FileName, ".java"):
		javaCmd := fmt.Sprintf("javac %s && java -cp /%s Main", safePath, projectName)
		runCmd = exec.Command("docker", "exec", containerID, "bash", "-c", javaCmd)
	default:
		http.Error(w, "Неподдерживаемый тип файла", http.StatusBadRequest)
		return
	}

	out, err := runCmd.CombinedOutput()
	if err != nil {
		http.Error(w, "Ошибка при выполнении файла: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(out)
}

// POST /project/{name}/file/create — создать пустой файл
func createFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	projectName := vars["name"]

	userID, err := getUserID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := checkProjectOwnership(projectName, userID); err != nil {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}
	dockerID, err := getDockerIDByProjectNameAndUser(projectName, userID)
	if err != nil {
		http.Error(w, "Проект не найден", http.StatusNotFound)
		return
	}

	var payload struct{ FileName string `json:"filename"` }
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}
	if payload.FileName == "" {
		http.Error(w, "Параметр filename обязателен", http.StatusBadRequest)
		return
	}
	safePath, err := sanitizeContainerPath(projectName, payload.FileName)
	if err != nil {
		http.Error(w, "Некорректный путь", http.StatusBadRequest)
		return
	}

	// запускаем touch внутри контейнера
	cmd := exec.Command("docker", "exec", dockerID, "bash", "-c", "touch "+safePath)
	if err := cmd.Run(); err != nil {
		http.Error(w, "Ошибка создания файла: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Файл создан"))
}