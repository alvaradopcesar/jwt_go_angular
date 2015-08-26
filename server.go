// Pruebas cli

/*

	-- test
	$ curl http://localhost:3000

	-- creating usuario
	$ curl --trace-ascii debugdump.txt http://localhost:3000/auth/login -d '{"email":"cesar","password":"kaisy"}' -H 'Content-Type: application/json'

	$ curl -H "Content-Type: application/json" -X POST -d '{"email":"cesar","password":"kaisy"}' http://127.0.0.1:3000/auth/login

	$ curl -H "Content-Type: application/json" -H "Access-Control-Request-Method: POST" -H "Access-Control-Allow-Origin: http://localhost:8000" -d '{"email":"cesar","password":"kaisy"}' http://127.0.0.1:3000/auth/login

	$ curl -H "Content-Type: application/json"  -d '{"email":"cesar","password":"kaisy"}' http://127.0.0.1:3000/auth/login

	$ curl -d '{"email":"cesar","password":"kaisy"}' http://127.0.0.1:3000/auth/login

	$ curl -H "Authorization : BEARER eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0Mzk1ODkyMzcsImlhdCI6MTQzODk4NDQzNywic3ViIjoiMTEifQ.aNm42-S1RgxwvdtT1_fvdfyfS0XxKOOFbQXP2n4ieto" http://127.0.0.1:3000/api/me

*/

package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	// "github.com/gorilla/mux"
	"net/http"
	// "os"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/context"
	"log"
	"strconv"
	"time"
	// "code.google.com/p/go.crypto/bcrypt"
)

const (
	tokenSecret = "keyboard cat"
	// tokenSecret = "token"
	tokenKey = 0
)

type User struct {
	Id       int64  `json:"id"`
	Email    string `json:"email"`
	Password string `json:"-"`
}

// func (u *User) SetPassword(password string) error {
// 	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 0)
// 	if err != nil {
// 		return err
// 	}
// 	u.Password = string(bytes)
// 	return nil
// }

// func (u *User) IsPassword(password string) bool {
// 	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) == nil
// }

type UserRepo struct {
	db *sql.DB
}

func (r *UserRepo) Find(user *User, id int64) error {
	q := r.db.QueryRow("SELECT id, email, password FROM users WHERE id=?", id)
	if err := q.Scan(&user.Id, &user.Email, &user.Password); err != nil {
		return err
	}
	return nil
}

func (r *UserRepo) FindByEmail(user *User, email string) error {
	q := r.db.QueryRow("SELECT id, email, password FROM users WHERE email=?", email)
	if err := q.Scan(&user.Id, &user.Email, &user.Password); err != nil {
		return err
	}
	return nil
}

func (r *UserRepo) Create(user *User) error {
	result, err := r.db.Exec("INSERT INTO users (email, password) VALUES (?, ?)", user.Email, user.Password)
	if err != nil {
		return err
	}
	user.Id, err = result.LastInsertId()
	return err
}

func JSON(response http.ResponseWriter, thing interface{}) {
	response.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(response)
	encoder.Encode(thing)
}

type jsonMessage struct {
	Message string `json:"message"`
}

func JSONMessage(response http.ResponseWriter, message string, code int) {
	response.WriteHeader(code)
	JSON(response, &jsonMessage{Message: message})
}

type authHandler struct {
	next http.Handler
}

func (h *authHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	// response.Header().Add("Access-Control-Allow-Origin", "http://127.0.0.1:8000")
	// response.Header().Add("Access-Control-Allow-Credentials", "true")
	// response.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	// response.Header().Set("Access-Control-Request-Method", "GET")

	// fmt.Println("----------------------")
	// fmt.Println("*authHandler 1")
	// fmt.Println(request)

	token, err := jwt.ParseFromRequest(request, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})
	fmt.Println(token)
	if err != nil || !token.Valid {
		JSONMessage(response, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	context.Set(request, tokenKey, token)
	h.next.ServeHTTP(response, request)
}

func AuthRequired(next http.Handler) http.Handler {
	return &authHandler{next: next}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginHandler struct {
	userRepo *UserRepo
}

func (h *loginHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	fmt.Println("Login en server ------------")

	// response.Header().Add("Access-Control-Allow-Origin", "*")
	// response.Header().Add("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")

	response.Header().Add("Access-Control-Allow-Origin", "http://localhost:8000")
	// response.Header().Add("Access-Control-Allow-Methods", "GET,PUT,OPTIONS,POST,DELETE")
	// response.Header().Add("Access-Control-Allow-Headers", "Cache-Control, Pragma, Origin, Authorization, Content-Type, X-Requested-With")
	// // response.Header().Add("Access-Control-Allow-Headers", "Content-Type, Authorization")
	// // response.Header().Add("Accept, Content-Type", "Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	response.Header().Add("Access-Control-Allow-Credentials", "true")

	// response.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:8000")
	// response.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	// response.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, X-PINGOTHER, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	// response.Header().Set("Connection", "keep-alive")
	// response.Header().Set("X-PINGOTHER", "pingpong")
	// response.Header().Set("Access-Control-Request-Method", "POST")
	// response.Header().Set("Access-Control-Request-Headers", "X-PINGOTHER")

	// response.Header().Set("Access-Control-Allow-Origin", "*")
	// response.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	// response.Header().Set("Access-Control-Allow-Methods", "POST")

	fmt.Println("Login en server 1")

	login := &loginRequest{}
	fmt.Println("Login en server 2")
	fmt.Println(request)
	fmt.Println("---**---")
	fmt.Println(request)
	// fmt.Println(*request)
	decoder := json.NewDecoder(request.Body)
	fmt.Println("Login en server 3")
	if err := decoder.Decode(login); err != nil {
		fmt.Println("Login en server 4 StatusBadRequest")
		fmt.Println(err.Error())
		JSONMessage(response, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Println(login.Email)
	fmt.Println("Login en server 5")
	user := &User{}
	if err := h.userRepo.FindByEmail(user, login.Email); err != nil {
		JSONMessage(response, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	fmt.Println(user.Password)
	fmt.Println(login.Password)
	// if !user.IsPassword(login.Password) {
	if !(user.Password == login.Password) {
		JSONMessage(response, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	token.Claims["iat"] = time.Now().Unix()
	token.Claims["exp"] = time.Now().Add(time.Hour * 24 * 7).Unix()
	token.Claims["sub"] = strconv.FormatInt(user.Id, 10) // spec says this must be a string
	strToken, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		JSONMessage(response, err.Error(), http.StatusInternalServerError)
	}
	fmt.Println("token : " + strToken)
	JSON(response, map[string]interface{}{"token": strToken})
}

type signupHandler struct {
	userRepo *UserRepo
}

func (h *signupHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	login := &loginRequest{}
	decoder := json.NewDecoder(request.Body)
	if err := decoder.Decode(login); err != nil {
		JSONMessage(response, err.Error(), http.StatusBadRequest)
		return
	}
	user := &User{}
	user.Email = login.Email
	// user.SetPassword(login.Password)
	user.Password = login.Password
	fmt.Println("creaando a ")
	fmt.Println(login.Email)
	fmt.Println(login.Password)
	if err := h.userRepo.Create(user); err != nil {
		JSONMessage(response, err.Error(), http.StatusInternalServerError)
		return
	}
	JSONMessage(response, "OK", http.StatusOK)
}

type meHandler struct {
	userRepo *UserRepo
}

func (h *meHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {

	// response.Header().Add("Access-Control-Allow-Origin", "http://127.0.0.1:8000")
	// response.Header().Add("Access-Control-Allow-Credentials", "true")
	// response.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	// response.Header().Set("Access-Control-Request-Method", "GET")

	token := context.Get(request, tokenKey).(*jwt.Token)
	id, err := strconv.ParseInt(token.Claims["sub"].(string), 10, 64)
	if err != nil {
		JSONMessage(response, err.Error(), http.StatusInternalServerError)
		return
	}
	user := &User{}
	if err := h.userRepo.Find(user, id); err != nil {
		JSONMessage(response, err.Error(), http.StatusInternalServerError)
		return
	}
	JSON(response, user)
}

func main() {
	// db, err := sql.Open("mysql", "user:password@/dbname")
	// db, err := sql.Open("mysql", "root:admin@/go_jwt_mysql")
	db, err := sql.Open("mysql", "root@tcp(127.0.0.1:3306)/go_jwt_mysql")
	if err != nil {
		panic(err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTO_INCREMENT,
		email CHAR(255) NOT NULL,
		password CHAR(255) NOT NULL
	)`); err != nil {
		panic(err)
	}

	userRepo := &UserRepo{db: db}

	// command line flags
	port := flag.Int("port", 3000, "port to serve on")
	dir := flag.String("directory", "FrontEnd/", "directory of web files")
	flag.Parse()

	http.Handle("/api/me", AuthRequired(&meHandler{userRepo: userRepo}))
	http.Handle("/auth/login", &loginHandler{userRepo: userRepo})
	http.Handle("/auth/signup", &signupHandler{userRepo: userRepo})

	// handle all requests by serving a file of the same name
	// fs := http.Dir(*dir)
	// fileHandler := http.FileServer(fs)
	// router := mux.NewRouter()
	// router.PathPrefix("/static/").Handler(http.StripPrefix("/static", fileHandler))
	// http.Handle("/", router)

	fs := http.Dir(*dir)
	fileHandler := http.FileServer(fs)
	http.Handle("/", fileHandler)

	log.Printf("Running on port %d\n", *port)

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	// this call blocks -- the progam runs here forever
	if err = http.ListenAndServe(addr, nil); err != nil {
		panic(err)
	}
}
