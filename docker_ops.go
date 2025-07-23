package main

import (
	"fmt"
  "log"
  "os/exec"
  "strings"
  "sync"
  "time"
)

const ChangesDir = "/data/changes"

var (
	// Для блокировки при работе с Docker
	mu sync.Mutex

	// Таймеры авто-стопа контейнеров
	containerStopTimers = make(map[string]*time.Timer)
	timersMu            sync.Mutex
)

func installLanguage(containerName, lang string) error {
	var cmd *exec.Cmd
	switch lang {
	case "python":
		cmd = exec.Command("docker", "exec", containerName, "apt", "install", "-y", "python3")
	case "node":
		cmd = exec.Command("docker", "exec", containerName, "apt", "install", "-y", "nodejs")
	case "dart":
		cmd = exec.Command("docker", "exec", containerName, "apt", "install", "-y", "dart")
	case "java":
		cmd = exec.Command("docker", "exec", containerName, "apt", "install", "-y", "default-jdk")
	case "go":
		cmd = exec.Command("docker", "exec", containerName, "apt", "install", "-y", "golang")
	case "php":
		cmd = exec.Command("docker", "exec", containerName, "apt", "install", "-y", "php")
	default:
		log.Printf("Язык %s не поддерживается, пропускаем", lang)
		return nil
	}
	log.Printf("Устанавливаем %s в контейнере %s", lang, containerName)
	return cmd.Run()
}

// Остановка контейнера
func stopContainer(containerName string) {
	cmd := exec.Command("docker", "stop", containerName)
	if err := cmd.Run(); err != nil {
		log.Printf("Ошибка остановки контейнера %s: %v", containerName, err)
	} else {
		log.Printf("Контейнер %s остановлен (бездействие 5 минут)", containerName)
	}
}

// Запуск/сброс таймера на остановку
func startStopTimer(containerName string) {
	timersMu.Lock()
	defer timersMu.Unlock()
	if timer, exists := containerStopTimers[containerName]; exists {
		timer.Stop()
	}
	timer := time.AfterFunc(5*time.Minute, func() {
		stopContainer(containerName)
		timersMu.Lock()
		delete(containerStopTimers, containerName)
		timersMu.Unlock()
	})
	containerStopTimers[containerName] = timer
}

// Отмена таймера
func cancelStopTimer(containerName string) {
	timersMu.Lock()
	defer timersMu.Unlock()
	if timer, exists := containerStopTimers[containerName]; exists {
		timer.Stop()
		delete(containerStopTimers, containerName)
	}
}

// Убедиться, что контейнер запущен
func ensureContainerRunning(containerName string) error {
	cmdStatus := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", containerName)
	output, err := cmdStatus.Output()
	if err != nil {
		return fmt.Errorf("не удалось проверить состояние: %v", err)
	}
	status := strings.TrimSpace(string(output))
	if status != "true" {
		cmdStart := exec.Command("docker", "start", containerName)
		if err := cmdStart.Run(); err != nil {
			return fmt.Errorf("не удалось запустить контейнер: %v", err)
		}
		log.Printf("Контейнер %s запущен", containerName)
	}
	return nil
}
