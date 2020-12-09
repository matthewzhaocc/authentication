package main

import (
	"net/http"
	"fmt"
	"gorm.io/gorm"
	"gorm.io/driver/sqlite"
	"time"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
)

var (
	userdb *gorm.DB
)

const (
	charset string = "abcdefghijklmnopqrstuvwxyz"
)

type User struct {
	gorm.Model
	Username string
	Password string
}

type Token struct {
	gorm.Model
	Username string
	Token string
	TTL time.Time
}

func Login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	Username := r.FormValue("username")
	Password := r.FormValue("password")
	var UserCtx User
	userdb.First(&UserCtx, "Username = ?", Username)

	res := bcrypt.CompareHashAndPassword([]byte(UserCtx.Password), []byte(Password))

	if res == nil {
		fmt.Fprintf(w, "success")
	} else {
		fmt.Fprintf(w, "failed")
		return
	}

	var seededRand *rand.Rand = rand.New(
		rand.NewSource(time.Now().UnixNano()))
	
	token := make([]byte, 8)
	for i := range token {
		token[i] = charset[seededRand.Intn(len(charset))] 
	}
	var tokenu Token
	tokenu.Username = Username
	userdb.Delete(&tokenu)
	Expire := time.Now()
	Expire.Add(15 * time.Minute)
	userdb.Create(&Token{Username: Username, Token: string(token), TTL: Expire})
	http.SetCookie(w, &http.Cookie{Name: "pass", Value: string(token)})
}

func Register(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	Username := r.FormValue("username")
	Password := r.FormValue("password")
	
	PasswordHash, _ := bcrypt.GenerateFromPassword([]byte(Password), 10)

	userdb.Create(&User{Username: Username, Password: string(PasswordHash)})
	fmt.Fprintf(w, "Successful")
}

func CheckToken(w http.ResponseWriter, r *http.Request) {
	token, _ := r.Cookie("pass")
	ReqToken := token.Value
	var TokenObj Token
	userdb.First(TokenObj, "Token = ?", ReqToken)
	if TokenObj.Token == "" {
		fmt.Fprintf(w, "failed")
		return
	}
	validation := datevalidate(TokenObj.TTL)
	if validation == true {
		fmt.Fprintf(w, "success")
		return
	}
	fmt.Fprintf(w, "failed")
}

func datevalidate(tokentime time.Time) bool{
	now := time.Now()
	return now.Before(tokentime)
}

func main() {
	userdb, _ = gorm.Open(sqlite.Open("user.db"), &gorm.Config{})
	userdb.AutoMigrate(&User{})
	userdb.AutoMigrate(&Token{})

	http.HandleFunc("/login", Login)
	http.HandleFunc("/register", Register)
	http.HandleFunc("/authcheck", CheckToken)
	http.ListenAndServe(":6443", nil)
}