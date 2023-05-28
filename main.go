package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type User struct {
	gorm.Model
	Name  string `gorm:"unique"`
	Email string `gorm:"unique"`
}

func main() {
	// db, err := gorm.Open("postgres", "host=db port=5432 user=postgres dbname=postgres password=password sslmode=disable")
	db, err := gorm.Open("postgres", "host=localhost port=5432 user=postgres dbname=postgres password=password sslmode=disable")

	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.AutoMigrate(&User{})

	router := mux.NewRouter()

	router.HandleFunc("/user", createUser(db)).Methods("POST")
	router.HandleFunc("/user", getAllUsers(db)).Methods("GET")
	router.HandleFunc("/user/{name}", getUser(db)).Methods("GET")

	log.Fatal(http.ListenAndServe(":8080", router))
}

func getUser(db *gorm.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		name := vars["name"]
		var user User
		if err := db.Where(&User{Name: name}).First(&user).Error; err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Couldn't find user with name %v\n", name)
			return
		}
		json.NewEncoder(w).Encode(user)
	}
}

func getAllUsers(db *gorm.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var users []User
		db.Find(&users)
		json.NewEncoder(w).Encode(users)
	}
}

func createUser(db *gorm.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var user User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "%v", errors.New("Invalid request payload"))
			return
		}
		if err := db.Create(&user).Error; err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "%v", err)
			return
		}
		json.NewEncoder(w).Encode(user)
	}
}
