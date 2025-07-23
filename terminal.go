package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"

	"github.com/creack/pty"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Обработчик WebSocket-терминала
func terminalHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    projectName := vars["name"]

    // Получаем userID из контекста
    userID, err := getUserID(r)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }

    // Проверяем владение проектом по имени И user_id
    if err := checkProjectOwnershipByName(projectName, userID); err != nil {
        http.Error(w, "Доступ запрещён", http.StatusForbidden)
        return
    }

    // Получаем dockerID проекта по имени И user_id
    dockerID, err := getDockerIDByProjectNameAndUser(projectName, userID)
    if err != nil {
        http.Error(w, "Проект не найден", http.StatusNotFound)
        return
    }

	// Убедимся, что контейнер работает (если нет — запустим)
	if err := ensureContainerRunning(dockerID); err != nil {
		http.Error(w, fmt.Sprintf("Ошибка запуска контейнера: %v", err), http.StatusInternalServerError)
		return
	}

	// Если у пользователя есть GitHub-токен, создаём .netrc внутри контейнера
	var ghToken, ghLogin sql.NullString
err = db.QueryRow(
	"SELECT github_token, github_login FROM users WHERE id = ?",
	userID,
).Scan(&ghToken, &ghLogin)
if err == nil && ghToken.Valid && ghLogin.Valid {
	decryptedToken, err := decryptToken(ghToken.String)
	if err != nil {
		log.Printf("Ошибка расшифровки GitHub токена: %v", err)
		return
	}

	netrcContent := fmt.Sprintf("machine github.com\n  login %s\n  password %s\n", ghLogin.String, decryptedToken)
	escaped := strings.ReplaceAll(netrcContent, `"`, `\"`)

	cmd := exec.Command(
		"docker", "exec", dockerID,
		"bash", "-c",
		fmt.Sprintf("echo \"%s\" > /root/.netrc && chmod 600 /root/.netrc", escaped),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Ошибка создания .netrc: %v; output=%s", err, out)
	}

	// Настроим git user.name и user.email, если ещё не указаны
	checkGitConfig := exec.Command("docker", "exec", dockerID, "git", "config", "--global", "--get", "user.name")
	if out, err := checkGitConfig.Output(); err != nil || len(out) == 0 {
		cmdGitConfig := exec.Command(
			"docker", "exec", dockerID,
			"bash", "-c",
			fmt.Sprintf("git config --global user.name \"%s\" && git config --global user.email \"%s@users.noreply.github.com\"",
				ghLogin.String, ghLogin.String),
		)
		if cfgOut, err := cmdGitConfig.CombinedOutput(); err != nil {
			log.Printf("Ошибка git config: %v; output=%s", err, cfgOut)
		}
	}
}


	// Отменяем таймер авто-стопа, если он был запущен
	cancelStopTimer(dockerID)

	

	// Апгрейдим соединение до WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Ошибка апгрейда до WebSocket:", err)
		return
	}
	defer conn.Close()

	// Проверяем, что контейнер существует (docker ps)
	cmdCheck := exec.Command("docker", "ps", "-q", "-f", "name="+dockerID)
	containerIDBytes, err := cmdCheck.Output()
	if err != nil || len(containerIDBytes) == 0 {
		conn.WriteMessage(websocket.TextMessage, []byte("Ошибка: контейнер не найден"))
		return
	}
	containerID := strings.TrimSpace(string(containerIDBytes))

	// Запускаем bash внутри контейнера через PTY
	cmdExec := exec.Command("docker", "exec", "-it", containerID, "bash")
	ptmx, err := pty.Start(cmdExec)
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("Ошибка запуска терминала: "+err.Error()))
		return
	}
	defer ptmx.Close()

	// Читаем вывод PTY и отправляем клиенту
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := ptmx.Read(buf)
			if err != nil {
				break
			}
			conn.WriteMessage(websocket.TextMessage, buf[:n])
		}
	}()

	// Читаем сообщения от клиента и пишем в PTY
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("Ошибка чтения из WebSocket:", err)
			updateProjectExitTime(projectName)
			startStopTimer(dockerID)
			break
		}
		if _, err := ptmx.Write(message); err != nil {
			log.Println("Ошибка записи в терминал:", err)
			updateProjectExitTime(projectName)
			startStopTimer(dockerID)
			break
		}
	}
}