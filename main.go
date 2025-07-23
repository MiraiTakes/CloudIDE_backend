package main

import (
	"log"
	"net"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	if err := initDB(); err != nil {
        log.Fatal("Ошибка подключения к базе данных:", err)
    }
    defer closeDB()

	r := mux.NewRouter()

	// Публичные (без JWT)
	r.HandleFunc("/register", registerUser).Methods("POST")
	r.HandleFunc("/login", loginUser).Methods("POST")
	r.HandleFunc("/auth/github/login", githubLogin).Methods("GET")
	r.HandleFunc("/auth/github/callback", githubCallback).Methods("GET")
	r.HandleFunc("/verify-code", verifyCode).Methods("POST")

	// Защищённые маршруты
	api := r.PathPrefix("/").Subrouter()
	api.Use(jwtMiddleware)

	// Проекты
	api.HandleFunc("/project", createProject).Methods("POST")
	api.HandleFunc("/project/{name}", deleteProject).Methods("DELETE")
	api.HandleFunc("/projects", getUserProjects).Methods("GET")
	api.HandleFunc("/projects/stats", getUserProjectsStats).Methods("GET")
	api.HandleFunc("/project/clone", cloneProject).Methods("POST")

	// Файлы, папки, запуск, изменения
	api.HandleFunc("/project/{name}/ws", terminalHandler).Methods("GET")
	api.HandleFunc("/project/{name}/files", listFiles).Methods("GET")
	api.HandleFunc("/project/{name}/file", saveFile).Methods("POST")
	api.HandleFunc("/project/{name}/file", getFileContent).Methods("GET")
	api.HandleFunc("/project/{name}/file", deleteFile).Methods("DELETE")
	api.HandleFunc("/project/{name}/run", runFile).Methods("POST")
	api.HandleFunc("/project/{name}/folder", createFolder).Methods("POST")
	api.HandleFunc("/project/{name}/move", moveFileOrFolder).Methods("POST")
	api.HandleFunc("/project/{name}/file/create", createFile).Methods("POST")
	api.HandleFunc("/project/{name}/changed-files", getChangedFilesHandler).Methods("GET")
	api.HandleFunc("/project/{name}/changed-files", postChangedFilesHandler).Methods("POST")

	// Пользовательский профиль
	api.HandleFunc("/users/{id}", getUserProfile).Methods("GET")

	log.Println("Server started on :8888")
	ln, err := net.Listen("tcp4", "0.0.0.0:8888")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.Serve(ln, r))
}
