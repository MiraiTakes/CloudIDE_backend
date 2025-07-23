package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func initDB() error {
	user := os.Getenv("DB_USER")
	pass := os.Getenv("DB_PASS")
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	name := os.Getenv("DB_NAME")

	if user == "" || pass == "" || host == "" || port == "" || name == "" {
		return fmt.Errorf("one or more required DB_* environment variables are not set")
	}

	params := "parseTime=true"
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?%s", user, pass, host, port, name, params)

	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("error opening DB: %v", err)
	}
	if err = db.Ping(); err != nil {
		return fmt.Errorf("error pinging DB: %v", err)
	}

	log.Println("Connected to DB successfully")
	return nil
}

func closeDB() {
	if db != nil {
		if err := db.Close(); err != nil {
			log.Println("Ошибка закрытия БД:", err)
		}
	}
}