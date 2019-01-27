package main

import(
	"net/http"
	"strconv"
	"database/sql"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"io/ioutil"
	"os"
	"time"
	"flag"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gocraft/web"
	_ "github.com/lib/pq"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

type Doc struct {
	Id	string	`json:"id"`
	Name	string	`json:"name"`
	Mime	string	`json:"mime"`
	Public	bool	`json:"public"`
	Created	string	`json:"created"`
	Author	string	`json:"author"`
	Grant	[]string `json:"grant"`
}

type Docs struct {
	Filename	string	`json:"file,omitempty"`
	DocsList	[]*Doc	`json:"docs,omitempty"`
}

type ReplyError struct {
	Code	int	`json:"code"`
	Text	string	`json:"text"`
}

type Response struct {
	Login	string	`json:"login,omitempty"`
	Token	string	`json:"token,omitempty"`
	Users	[]string `json:"users,omitempty"`
}

type ReplyModel struct {
	Err	*ReplyError	`json:"error,omitempty"`
	Res	*Response	`json:"response,omitempty"`
	Data	*Docs		`json:"data,omitempty"`
}

type RegisterForm struct {
	Login		string	`json:"login"`
	Password	string	`json:"pswd"`
}

type Context struct {
	Error	error
}

//Custom middleware logger
func (c *Context) Log(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc){
	start := time.Now()
	next(rw, req)
	glog.Infof("[%s] [%s %s]", time.Since(start), req.Method, req.URL)
}

//Custom middleware error handler
func (c *Context) HandleError(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc){
	next(rw, req)

	if (c.Error != nil) {
		glog.Infof("[ERROR] [%s %s] while %s", req.Method, req.URL, c.Error)
		var code int
		var text string

		switch rw.StatusCode() {
			case 400:
				code = 400
				text = "Bad request"
			case 401:
				code = 401
				text = "Unauthorized"
			case 403:
				code = 403
				text = "Forbidden"
			case 404:
				code = 404
				text = "Not found"
			case 405:
				code = 405
				text = "Method not allowed"
			case 500:
				code = 500
				text = "Internal server error"
			case 501:
				code = 501
				text = "Not implemented"
			case 503:
				code = 503
				text = "Service unavailable"
			default:
				code = 500
				text = "Internal server error"
		}

		reply := &ReplyModel{
			Err: &ReplyError{
				Code: code,
				Text: text,
			},
		}

		c.Reply(rw, req, reply)
		return
	}
}

//Universal replying method
func (c *Context) Reply(rw web.ResponseWriter, req *web.Request, model *ReplyModel){
	reply, err := json.MarshalIndent(model, "", " ")
	if (err != nil) {
		c.Error = err
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(reply)
}

//Authentication checking middleware
func (c *Context) AuthCheck(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc){
	var lastActivityTime time.Time
	var login string

	token, err := req.Cookie("token")
	if (err != nil) {
		if (err == http.ErrNoCookie){
			c.Error = errors.Wrap(err, "signing in without cookie")
			HandleBadAuthResponse(rw, req, http.StatusUnauthorized)
			return
		}
		c.Error = errors.Wrap(err, "parsing token")
		HandleBadAuthResponse(rw, req, http.StatusUnauthorized)
		return
	}

	loginFromCookie, err := req.Cookie("login")
	if (err != nil) {
		if (err == http.ErrNoCookie){
			c.Error = errors.Wrap(err, "signing in without login")
			HandleBadAuthResponse(rw, req, http.StatusUnauthorized)
			return
		}
		c.Error = errors.Wrap(err, "parsing ligin")
		HandleBadAuthResponse(rw, req, http.StatusUnauthorized)
		return
	}

	err = db.QueryRow(`SELECT lastactivitytime, login FROM sessions WHERE token = $1;`, token.Value).Scan(&lastActivityTime, &login)
	if (err != nil) {
		if (err == sql.ErrNoRows){
			c.Error = errors.Wrap(err, "trying to sign in with bad token")
			HandleBadAuthResponse(rw, req, http.StatusUnauthorized)
			return
		}
		c.Error = errors.Wrap(err, "searching for appropriate token in db")
		HandleBadAuthResponse(rw, req, http.StatusUnauthorized)
		return
	}

	if (loginFromCookie.Value != login) {
		err = errors.New("bad login")
		c.Error = errors.Wrap(err, "signing in with bad login")
		HandleBadAuthResponse(rw, req, http.StatusUnauthorized)
		return
	}


	_, err = db.Exec(`UPDATE sessions SET lastactivitytime = now() where token = $1;`, token.Value)
	if (err != nil) {
		c.Error = errors.Wrap(err, "updating session token")
		HandleBadAuthResponse(rw, req, http.StatusInternalServerError)
		return
	}

	next(rw, req)
}

func HandleBadAuthResponse(rw web.ResponseWriter, req *web.Request, status int){
	if (req.RequestURI == "/docs") {
		http.Redirect(rw, req.Request, "/login", http.StatusFound)
	} else {
		rw.WriteHeader(status)
	}
}

var(
	db	*sql.DB
	cache = make(map[string]Doc)
	cacheIsRelevant = false
	mutex	sync.RWMutex
)

func SetCacheRelevant(){
	cacheIsRelevant = true
}

func SetCacheIrrelevant(){
	mutex.Lock()
	cache = make(map[string]Doc)
	cacheIsRelevant = false
	mutex.Unlock()
}

func WriteToCache(key string, value Doc){
	mutex.Lock()
	cache[key] = value
	mutex.Unlock()
}

func ReadFromCache(key string) (Doc, error){
	mutex.RLock()
	data, ok := cache[key]
	mutex.RUnlock()
	if (ok == false){
		return data, errors.New("no such a value in cache")
	}
	return data, nil
}

//Clears tokens associated with innactive users
func ClearSessions() (error) {
	_, err := db.Exec(`DELETE FROM sessions WHERE lastactivitytime < current_timestamp - interval '1 hour';`)
	if (err != nil) {
		return err
	}
	return nil
}

func main() {
	flag.Set("logtostderr", "true")
	flag.Set("v", "2")
	flag.Parse()

	//var err error

	db_login, err := ioutil.ReadFile("./db_login.txt") //db_login.txt: "username:password"
	if (err != nil) {
		glog.Infof("[ERROR] in main(!) while openning db_login.txt: %s", err)
	}

	connectionString := "postgres://" + strings.TrimRight(string(db_login), "\r\n") + "@localhost/cachingserverdb"

	db, err = sql.Open("postgres", connectionString);
	if (err != nil) {
		glog.Infof("[ERROR] in main(!) while opening db: %s", err)
		return
	}
	defer db.Close()

	//Initiate sessions cleaning every 30 minutes
	ticker := time.NewTicker(30 * time.Minute)
	go func() {
		for _ = range ticker.C {
			err := ClearSessions()
			if (err != nil) {
				glog.Infof("[ERROR] in main(!) while clearing sessions: ", err)
				return
			}
		}
	}()

	router := web.New(Context{}).
		Middleware((*Context).Log).
		Middleware((*Context).HandleError)
	//API definition goes here
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Get("api/docs", (*Context).GetDocsRoute)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Get("api/docs/:id", (*Context).GetDocByIdRoute)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Post("api/docs", (*Context).PostDocRoute)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Delete("api/docs/:id", (*Context).DeleteDocRoute)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Delete("api/auth", (*Context).DeleteAuthRoute)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Post("api/grant", (*Context).GrantPermissionsRoute)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Delete("api/grant", (*Context).CancelPermissionsRoute)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Post("api/grant/public/:id", (*Context).SetDocPublic)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Post("api/grant/private/:id", (*Context).SetDocPrivate)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Get("api/users", (*Context).GetUsersListRoute)
	router.Post("api/register", (*Context).PostRegisterRoute)
	router.Post("api/auth", (*Context).PostAuthRoute)

	//Pages definition goes here
	router.Get("/", (*Context).RootRoute)
	router.Get("/registration", (*Context).RegistrationPage)
	router.Get("/login", (*Context).LoginPage)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Get("/docs", (*Context).DocsPage)

	glog.Infof("Server started at port 8000")
	http.ListenAndServe("localhost:8000", router)
}

//Pages controllers goes here
//GET /
func (c *Context) RootRoute(rw web.ResponseWriter, req *web.Request){
	http.Redirect(rw, req.Request, "/docs", http.StatusFound)
}

//GET /registration
func (c *Context) RegistrationPage(rw web.ResponseWriter, req *web.Request){
	rw.Header().Set("Content-Type", "text/html")
	http.ServeFile(rw, req.Request, "./public/registration.html")
}

//GET /login
func (c *Context) LoginPage(rw web.ResponseWriter, req *web.Request){
	rw.Header().Set("Content-Type", "text/html")
	http.ServeFile(rw, req.Request, "./public/login.html")
}

//GET /docs
func (c *Context) DocsPage(rw web.ResponseWriter, req *web.Request){
	rw.Header().Set("Content-Type", "text/html")
	http.ServeFile(rw, req.Request, "./public/docs.html")
}


//API controllers goes here
//POST /api/docs
func (c *Context) PostDocRoute(rw web.ResponseWriter, req *web.Request){
	userLogin, err := req.Cookie("login")
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing login")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	err = req.ParseMultipartForm(16 << 20) //16 MiB
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing form")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	file, fileHeader, err := req.FormFile("newdoc")
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing file")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	defer file.Close()

	content, err  := ioutil.ReadAll(file)
	if (err != nil) {
		c.Error = errors.Wrap(err, "reading file")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	savePath := filepath.Join("./UserFiles/" + userLogin.Value + "/" + fileHeader.Filename)
	_, err = filepath.Rel(filepath.Join("UserFiles/" + userLogin.Value), savePath)
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing filename")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	_, err = os.Stat(savePath)
	if (os.IsNotExist(err)) {
		err = ioutil.WriteFile(savePath, content, os.ModePerm)
		if (err != nil) {
			c.Error = errors.Wrap(err, "saving file on disk")
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		err = errors.New("file already exists")
		c.Error = errors.Wrap(err, "creating already existing file")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	var name = fileHeader.Filename
	var mime = fileHeader.Header.Get("Content-Type")
	var public = req.FormValue("isPublic")
	var id string
	err = db.QueryRow(`
		INSERT INTO docs (name, mime, public, author) 
		VALUES ($1, $2, $3, $4)
		RETURNING id;`, name, mime, public, userLogin.Value).Scan(&id)
	if (err != nil) {
		c.Error = errors.Wrap(err, "inserting into docs table")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(`
		INSERT INTO permits (docId, login) 
		VALUES ($1, $2);`, id, userLogin.Value)
	if (err != nil) {
		c.Error = errors.Wrap(err, "inserting into permits table")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	SetCacheIrrelevant()

	reply := &ReplyModel{
		Data: &Docs{
			Filename: name,
		},
	}


	rw.WriteHeader(http.StatusCreated)
	c.Reply(rw, req, reply)
}

//GET /api/docs
func (c *Context) GetDocsRoute(rw web.ResponseWriter, req *web.Request){
	var countOfDocs int

	limit := req.URL.Query().Get("limit")

	userLogin, err := req.Cookie("login")
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing login")
		rw.WriteHeader(http.StatusForbidden)
		return
	}


	if (limit != "") {
		countOfDocs, err = strconv.Atoi(limit)
		if err != nil{
			countOfDocs = 0
		}
	}

	if (cacheIsRelevant) {
		userDocs := new(Docs)
		for _, value := range cache{
			var doc = value
			if (doc.Public == true) {
				userDocs.DocsList = append(userDocs.DocsList, &doc)
				continue
			}

			for _, user := range doc.Grant {
				if (user == userLogin.Value) {
					userDocs.DocsList = append(userDocs.DocsList, &doc)
				}
			}
		}

		if (countOfDocs > 0 && countOfDocs < len(userDocs.DocsList)) {
			userDocs.DocsList = userDocs.DocsList[:countOfDocs]
		}

		reply := &ReplyModel{
			Data: userDocs,
		}
		rw.WriteHeader(http.StatusOK)
		c.Reply(rw, req, reply)
	} else {
		result, err := db.Query(`
				SELECT id, name, mime, public, created_at, author, login
				FROM docs
				INNER JOIN permits ON docs.id = permits.docid
				ORDER BY id;`)

		if (err != nil){
			SetCacheIrrelevant()
			c.Error = errors.Wrap(err, "querying")
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer result.Close()

		docs := new(Docs)
		docPrev := new(Doc)
		docNew := new(Doc)
		var fileRemains bool
		var login string
		for result.Next(){
			docPrev = docNew
			docNew = new(Doc)
			err = result.Scan(&docNew.Id, &docNew.Name, &docNew.Mime, &docNew.Public, &docNew.Created, &docNew.Author, &login)
			if (err != nil){
				SetCacheIrrelevant()
				c.Error = errors.Wrap(err, "scanning result")
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}

			if (docPrev.Id == "") {
				docNew.Grant = append(docNew.Grant, login)
				fileRemains = true
				continue
			}

			if (docNew.Id == docPrev.Id) {
				docNew.Grant = append(docPrev.Grant, login)
				fileRemains = true
				continue
			}

			if (docNew.Id != docPrev.Id) {
				docs.DocsList = append(docs.DocsList, docPrev)
				WriteToCache(docPrev.Id, *docPrev)
				if (docNew.Public == true) {
					docs.DocsList = append(docs.DocsList, docNew)
					WriteToCache(docNew.Id, *docNew)
					docNew = new(Doc)
					fileRemains = false
					continue
				}
				docNew.Grant = append(docNew.Grant, login)
				fileRemains = true
				continue
			}

			if (docNew.Public == true) {
				docs.DocsList = append(docs.DocsList, docNew)
				WriteToCache(docNew.Id, *docNew)
				docNew = new(Doc)
				fileRemains = false
				continue
			}


		}

		if (fileRemains == true) {
			docs.DocsList = append(docs.DocsList, docNew)
			WriteToCache(docNew.Id, *docNew)
		}

		if err = result.Err(); err != nil {
			SetCacheIrrelevant()
			c.Error = errors.Wrap(err, "after delving in result")
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		userDocs := new(Docs)
		for _, doc := range docs.DocsList{
			if (doc.Public == true) {
				userDocs.DocsList = append(userDocs.DocsList, doc)
				continue
			}

			for _, user := range doc.Grant {
				if (user == userLogin.Value) {
					userDocs.DocsList = append(userDocs.DocsList, doc)
				}
			}
		}

		if (countOfDocs > 0 && countOfDocs < len(userDocs.DocsList)) {
			userDocs.DocsList = userDocs.DocsList[:countOfDocs]
		}

		SetCacheRelevant()

		reply := &ReplyModel{
			Data: userDocs,
		}

		rw.WriteHeader(http.StatusOK)
		c.Reply(rw, req, reply)
	}
}

//GET /api/docs/:id
func (c *Context) GetDocByIdRoute(rw web.ResponseWriter, req *web.Request){
	userLogin, err := req.Cookie("login")
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing login")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	var docPath string
	var docId = req.PathParams["id"]

	doc, ok := cache[docId]
	if ok {
		docPath = filepath.Join("./UserFiles/" + doc.Author + "/" + doc.Name)
		if (doc.Public == true) {
			rw.Header().Set("Content-Type", doc.Mime)
			http.ServeFile(rw, req.Request, docPath)
			return
		} else {
			for _, user := range doc.Grant {
				if (user == userLogin.Value) {
					rw.Header().Set("Content-Type", doc.Mime)
					http.ServeFile(rw, req.Request, docPath)
					return
				}
			}
			err = errors.New("this file is not for user " + userLogin.Value)
			c.Error = errors.Wrap(err, "accessing forbidden file")
			rw.WriteHeader(http.StatusForbidden)
			return
		}

	} else {
		var login string

		result, err := db.Query(`SELECT id, name, mime, public, created_at, author, login 
				FROM docs 
				INNER JOIN permits ON docs.id = permits.docid
				WHERE id=$1`, docId)
		if (err != nil){
			if (err == sql.ErrNoRows) {
				c.Error = errors.Wrap(err, "trying to access file with bad id")
				rw.WriteHeader(http.StatusNotFound)
				return
			}
			c.Error = errors.Wrap(err, "querying file")
			rw.WriteHeader(http.StatusNotFound)
			return
		}
		defer result.Close()

		doc := new(Doc)
		for result.Next(){
			err = result.Scan(&doc.Id, &doc.Name, &doc.Mime, &doc.Public, &doc.Created, &doc.Author, &login)
			if (doc.Public == true || login == userLogin.Value) {
				WriteToCache(doc.Id, *doc)
				SetCacheIrrelevant()

				docPath = filepath.Join("./UserFiles/" + doc.Author + "/" + doc.Name)
				rw.Header().Set("Content-Type", doc.Mime)
				http.ServeFile(rw, req.Request, docPath)
				return
			}
		}
	}
	err = errors.New("file not found")
	c.Error = errors.Wrap(err, "searching for file")
	rw.WriteHeader(http.StatusNotFound)
	return
}

//DELETE /api/docs/:id
func (c *Context) DeleteDocRoute(rw web.ResponseWriter, req *web.Request){
	userLogin, err := req.Cookie("login")
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing login")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	docId := req.PathParams["id"]

	mutex.RLock()
	_, ok := cache[docId]
	if (ok) {
		delete(cache, docId)
	}
	mutex.RUnlock()

	var doc = new(Doc)
	err = db.QueryRow(`
			SELECT name, author
			FROM docs
			WHERE id = $1`, docId).Scan(&doc.Name, &doc.Author)
	if (err != nil) {
		if (err == sql.ErrNoRows) {
			c.Error = errors.Wrap(err, "trying to delet file using bad id")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		c.Error = errors.Wrap(err, "querying db")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if (doc.Author == userLogin.Value) {
		_, err = db.Exec(`
			DELETE
			FROM docs
			WHERE id = $1`, docId)
		if (err != nil) {
			c.Error = errors.Wrap(err, "deleting file from docs table")
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		docPath := filepath.Join("./UserFiles" + userLogin.Value + "/" + doc.Name)
		_, err = os.Stat(docPath)
		if (os.IsNotExist(err)) {
			err = errors.New("there is no such a file")
			c.Error = errors.Wrap(err, "trying to delete file, which doesn't exist")
			rw.WriteHeader(http.StatusBadRequest)
		} else {
			err = os.Remove(docPath)
			if (err != nil) {
				c.Error = errors.Wrap(err, "deleting file " + docPath)
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}
			rw.WriteHeader(http.StatusOK)
			return
		}
	} else {
		err = errors.New("file may be deleted only by author")
		c.Error = errors.Wrap(err, "deleting someone's else file")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

}

//POST /api/register
func (c *Context) PostRegisterRoute(rw web.ResponseWriter, req *web.Request){
	var regForm	RegisterForm

	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&regForm)
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing register form")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	rege := regexp.MustCompile("^(.\\d?)(.\\D?)([a-zA-Z0-9_]{6,20})$")
	authCheck := rege.MatchString(regForm.Login)
	if (!authCheck) {
		c.Error = errors.Wrap(err, "registering with bad login")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	authCheck = rege.MatchString(regForm.Password)
	if (!authCheck) {
		c.Error = errors.Wrap(err, "registering with bad password")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	dirPath := filepath.Join("./UserFiles/" + regForm.Login + "/")
	err = os.MkdirAll(dirPath, os.ModePerm)
	if (err != nil) {
		c.Error = errors.Wrap(err, "creating user directory")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	pswdHash := sha256.Sum256([]byte(regForm.Password))
	pswdHashStr := hex.EncodeToString(pswdHash[:])
	_, err = db.Exec(`INSERT INTO users (login, password) VALUES ($1, $2)`, regForm.Login, pswdHashStr)
	if (err != nil) {
		c.Error = errors.Wrap(err, "creating new user")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	reply := &ReplyModel{
		Res: &Response{
			Login: regForm.Login,
		},
	}
	rw.WriteHeader(http.StatusCreated)
	c.Reply(rw, req, reply)
}

//POST /api/auth
func (c *Context) PostAuthRoute(rw web.ResponseWriter, req *web.Request){
	var authForm	RegisterForm
	var login	string
	var password	string

	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&authForm)
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing auth form")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	pswdHash := sha256.Sum256([]byte(authForm.Password))
	pswdHashStr := hex.EncodeToString(pswdHash[:])

	err = db.QueryRow(`SELECT login, password FROM users WHERE login = $1 and password = $2;`, authForm.Login, pswdHashStr).Scan(&login, &password)
	if (err != nil) {
		if (err == sql.ErrNoRows) {
			c.Error = errors.Wrap(err, "authenticating with wrong credentials")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		c.Error = errors.Wrap(err, "querying users")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	tokenRaw, err := uuid.NewV4()
	if (err != nil) {
		c.Error = errors.Wrap(err, "generating token")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(`INSERT INTO sessions (login, token) VALUES($1, $2)`, authForm.Login, tokenRaw.String())
	if (err != nil) {
		c.Error = errors.Wrap(err, "creating session for user " + authForm.Login)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	reply := &ReplyModel{
		Res: &Response{
			Login: authForm.Login,
			Token: tokenRaw.String(),
		},
	}

	http.SetCookie(rw, &http.Cookie{Name: "token", Value: tokenRaw.String(), Path: "/"})
	http.SetCookie(rw, &http.Cookie{Name: "login", Value: authForm.Login, Path: "/"})
	rw.Header().Set("Location", "/docs")
	rw.WriteHeader(http.StatusOK)
	c.Reply(rw, req, reply)
}

//DELETE /api/auth
func (c *Context) DeleteAuthRoute(rw web.ResponseWriter, req *web.Request){
	token, err := req.Cookie("token")
	if (err != nil) {
		if (err == http.ErrNoCookie){
			c.Error = errors.Wrap(err, "logging out without token")
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		c.Error = errors.Wrap(err, "parsing token")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	_, err = db.Exec(`DELETE FROM sessions WHERE token = $1;`, token.Value)
	if (err != nil) {
		if (err == sql.ErrNoRows) {
			c.Error = errors.Wrap(err, "logging out with unknown token")
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		c.Error = errors.Wrap(err, "deleting from session table")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	reply := &ReplyModel{
		Res: &Response{
			Token: "DELETED",
		},
	}

	http.SetCookie(rw, &http.Cookie{Name: "token", Value: "", Path: "/"})
	rw.WriteHeader(http.StatusOK)
	c.Reply(rw, req, reply)
}

//POST /api/grant
func (c *Context) GrantPermissionsRoute(rw web.ResponseWriter, req *web.Request){
	var author string

	userLogin, err := req.Cookie("login")
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing login")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	login := req.URL.Query().Get("login")
	docId := req.URL.Query().Get("docid")

	err = db.QueryRow(`
			SELECT author
			FROM docs
			WHERE id = $1`, docId).
		Scan(&author)
	if (err != nil) {
		if (err == sql.ErrNoRows){
			c.Error = errors.Wrap(err, "trying to grant using bad docId")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		c.Error = errors.Wrap(err, "trying to retrieve author")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if (author != userLogin.Value) {
		err = errors.New("only author can give permissions")
		c.Error = errors.Wrap(err, "trying to grant permissions to someone's else file")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	_, err = db.Exec(`INSERT INTO permits (docid, login) VALUES ($1, $2)`, docId, login)
	if (err != nil) {
		c.Error = errors.Wrap(err, "granting rights")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	SetCacheIrrelevant()
	reply := &ReplyModel{
		Res: &Response{
			Login: login,
		},
	}
	rw.WriteHeader(http.StatusOK)
	c.Reply(rw, req, reply)
}

//DELETE /api/grant
func (c *Context) CancelPermissionsRoute(rw web.ResponseWriter, req *web.Request){
	var author string

	userLogin, err := req.Cookie("login")
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing login")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	login := req.URL.Query().Get("login")
	docId := req.URL.Query().Get("docid")

	err = db.QueryRow(`
			SELECT author
			FROM docs
			WHERE id = $1`, docId).
		Scan(&author)
	if (err != nil) {
		if (err == sql.ErrNoRows){
			c.Error = errors.Wrap(err, "trying to cancel permissions using bad docId")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		c.Error = errors.Wrap(err, "trying to retrieve author")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if (author != userLogin.Value) {
		err = errors.New("only author can cancel permissions")
		c.Error = errors.Wrap(err, "trying to cancel permissions to someone's else file")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	_, err = db.Exec(`DELETE FROM permits WHERE docid = $1 and login = $2`, docId, login)
	if (err != nil) {
		c.Error = errors.Wrap(err, "canceling permissions")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	SetCacheIrrelevant()
	reply := &ReplyModel{
		Res: &Response{
			Login: login,
		},
	}
	rw.WriteHeader(http.StatusOK)
	c.Reply(rw, req, reply)
}

//POST /api/grant/public/:id
func (c *Context) SetDocPublic(rw web.ResponseWriter, req *web.Request){
	var author string

	userLogin, err := req.Cookie("login")
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing login")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	docId := req.PathParams["id"]

	err = db.QueryRow(`
			SELECT author
			FROM docs
			WHERE id = $1`, docId).
		Scan(&author)
	if (err != nil) {
		if (err == sql.ErrNoRows){
			c.Error = errors.Wrap(err, "trying to set file public using bad docId")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		c.Error = errors.Wrap(err, "trying to retrieve author")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if (author != userLogin.Value) {
		err = errors.New("only author can set file public")
		c.Error = errors.Wrap(err, "trying to set someone's else file public")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	_, err = db.Exec(`UPDATE docs SET public = true WHERE id = $1`, docId)
	if (err != nil) {
		c.Error = errors.Wrap(err, "setting file public")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	SetCacheIrrelevant()
	reply := &ReplyModel{
		Res: &Response{
			Token: "OK",
		},
	}
	rw.WriteHeader(http.StatusOK)
	c.Reply(rw, req, reply)

}

//POST /api/grant/private/:id
func (c *Context) SetDocPrivate(rw web.ResponseWriter, req *web.Request){
	var author string

	userLogin, err := req.Cookie("login")
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing login")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	docId := req.PathParams["id"]

	err = db.QueryRow(`
			SELECT author
			FROM docs
			WHERE id = $1`, docId).
		Scan(&author)
	if (err != nil) {
		if (err == sql.ErrNoRows){
			c.Error = errors.Wrap(err, "trying to set file private using bad docId")
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		c.Error = errors.Wrap(err, "trying to retrieve author")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	if (author != userLogin.Value) {
		err = errors.New("only author can set file private")
		c.Error = errors.Wrap(err, "trying to set someone's else file private")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	_, err = db.Exec(`UPDATE docs SET public = false WHERE id = $1`, docId)
	if (err != nil) {
		c.Error = errors.Wrap(err, "setting file private")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	SetCacheIrrelevant()
	reply := &ReplyModel{
		Res: &Response{
			Token: "OK",
		},
	}
	rw.WriteHeader(http.StatusOK)
	c.Reply(rw, req, reply)

}

//GET /api/users
func (c *Context) GetUsersListRoute(rw web.ResponseWriter, req *web.Request){
	userLogin, err := req.Cookie("login")
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing login")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	result, err := db.Query(`SELECT login FROM users`)
	if (err != nil) {
		c.Error = errors.Wrap(err, "getting list of users")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer result.Close()

	var users []string
	var user string
	for result.Next(){
		err = result.Scan(&user)
		if (err != nil) {
			c.Error = errors.Wrap(err, "parsing result")
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		if (userLogin.Value != user) {
			users = append(users, user)
		}
	}

	reply := &ReplyModel{
		Res: &Response{
			Users: users,
		},
	}
	rw.WriteHeader(http.StatusOK)
	c.Reply(rw, req, reply)


}
