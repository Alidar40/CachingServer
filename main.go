package main

import(
	"fmt"
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

func (c *Context) Log(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc){
	start := time.Now()
	next(rw, req)
	glog.Infof("[%s] [%s %s]", time.Since(start), req.Method, req.URL)
}

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

func (c *Context) Reply(rw web.ResponseWriter, req *web.Request, model *ReplyModel){
	reply, err := json.MarshalIndent(model, "	", "	")
	if (err != nil) {
		c.Error = err
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(reply)
}

func (c *Context) AuthCheck(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc){
	var lastActivityTime time.Time
	var login string

	token, err := req.Cookie("token")
	if (err != nil) {
		if (err == http.ErrNoCookie){
			c.Error = errors.Wrap(err, "signing in without cookie")
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		c.Error = errors.Wrap(err, "parsing token")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = db.QueryRow(`SELECT lastactivitytime, login FROM sessions WHERE token = $1;`, token.Value).Scan(&lastActivityTime, &login)
	if (err != nil) {
		if (err == sql.ErrNoRows){
			c.Error = errors.Wrap(err, "trying to sign in with bad token")
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		c.Error = errors.Wrap(err, "searching for appropriate token in db")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	loginFromCookie, err := req.Cookie("login")
	if (err != nil) {
		if (err == http.ErrNoCookie){
			c.Error = errors.Wrap(err, "signing in without login")
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		c.Error = errors.Wrap(err, "parsing ligin")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	if (loginFromCookie.Value != login) {
		err = errors.New("bad login")
		c.Error = errors.Wrap(err, "signing in with bad login")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	_, err = db.Exec(`UPDATE sessions SET lastactivitytime = now() where token = $1;`, token.Value)
	if (err != nil) {
		c.Error = errors.Wrap(err, "updating session token")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	next(rw, req)
}

var(
	db	*sql.DB
	cache = make(map[string]Doc)
	cacheIsRelevant = false
	mutex	sync.Mutex
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
	mutex.Lock()
	data, ok := cache[key]
	if (ok == false){
		mutex.Unlock()
		return data, errors.New("no such a value in cache")
	}
	mutex.Unlock()
	return data, nil
}

func VerifyRegisterParameters(parameter string, isPswd bool) (error){
	var err		error
	var i		int
	var isLetter	bool
	var isDigit	bool

	var containsDigit	bool
	var containsLetter	bool


	if (len(parameter) < 8 || len(parameter) > 32){
		err = errors.New("parameter is either too short, or too long")
		return err
	}

	for i = 0; i < len(parameter); i++ {
		isLetter = false
		isDigit = false

		symbol, err := strconv.Atoi(fmt.Sprintf("%d", parameter[i]))
		if (err != nil) {
			return err
		}

		/*ASCII:-------A---------------Z-----------------a---------------z*/
		if ((symbol >= 65 && symbol <= 90) || (symbol >= 97 && symbol <= 122)) {
			isLetter = true
			if (isPswd) {
				containsLetter = true
			}
		}

		/*ASCII:------0---------------9*/
		if (symbol >= 48 && symbol <= 57) {
			isDigit = true
			if (isPswd) {
				containsDigit = true
			}
		}

		if (isDigit == false && isLetter == false) {
			err = errors.New("one of characters is niether a letter, nor a digit")
			return err
		}
	}

	if (isPswd == true && (containsLetter == false || containsDigit == false)){
		err = errors.New("password must contain at least one digit and one letter")
		return err
	}
	return nil
}

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

	var err error
	db, err = sql.Open("postgres", "postgres://alidar:1@localhost/cachingserverdb");
	if (err != nil){
		glog.Infof("[ERROR] in main(!) while opening db: %s", err)
		return
	}
	defer db.Close()

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
	router.Get("/", (*Context).RootRoute)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Get("/docs", (*Context).GetDocsRoute)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Get("/docs/:id", (*Context).GetDocByIdRoute)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Post("/docs", (*Context).PostDocRoute)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Delete("/docs/:id", (*Context).DeleteDocRoute)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Delete("/auth", (*Context).DeleteAuthRoute)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Post("/grant", (*Context).GrantPermissionsRoute)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Delete("/grant", (*Context).CancelPermissionsRoute)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Post("/grant/public/:id", (*Context).SetDocPublic)
	router.Subrouter(Context{}, "/").Middleware((*Context).AuthCheck).Post("/grant/private/:id", (*Context).SetDocPrivate)
	router.Post("/register", (*Context).PostRegisterRoute)
	router.Post("/auth", (*Context).PostAuthRoute)
	http.ListenAndServe("localhost:8000", router)
}

func (c *Context) RootRoute(rw web.ResponseWriter, req *web.Request){
	fmt.Fprint(rw, "Hi there")
}

func (c *Context) PostDocRoute(rw web.ResponseWriter, req *web.Request){
	userLogin, err := req.Cookie("login")
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing login")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	err = req.ParseMultipartForm(16777216) //16 MiB
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

	_, err = os.Stat("./UserFiles/" + userLogin.Value + "/" + fileHeader.Filename)
	if (os.IsNotExist(err)) {
		err = ioutil.WriteFile("./UserFiles/" + userLogin.Value + "/" + fileHeader.Filename, content, os.ModePerm)
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
	_, err = db.Exec(`
		INSERT INTO docs (name, mime, public, author) 
		VALUES ($1, $2, $3, $4);`, name, mime, public, userLogin.Value)
	if (err != nil) {
		c.Error = errors.Wrap(err, "inserting into docs table")
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	var id string
	err = db.QueryRow(`
			SELECT id
			FROM docs
			WHERE name = $1 and author = $2;`, name, userLogin.Value).
		Scan(&id)
	if (err != nil) {
		c.Error = errors.Wrap(err, "getting doc's id")
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

func (c *Context) GetDocByIdRoute(rw web.ResponseWriter, req *web.Request){
	userLogin, err := req.Cookie("login")
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing login")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	var docId = req.PathParams["id"]

	doc, ok := cache[docId]
	if ok {
		if (doc.Public == true) {
			rw.Header().Set("Content-Type", doc.Mime)
			http.ServeFile(rw, req.Request, "./UserFiles/" + doc.Author + "/" + doc.Name)
			return
		} else {
			for _, user := range doc.Grant {
				if (user == userLogin.Value) {
					rw.Header().Set("Content-Type", doc.Mime)
					http.ServeFile(rw, req.Request, "./UserFiles/" + doc.Author + "/" + doc.Name)
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

				rw.Header().Set("Content-Type", doc.Mime)
				http.ServeFile(rw, req.Request, "./UserFiles/" + doc.Author + "/" + doc.Name)
				return
			}
		}
	}
	err = errors.New("file not found")
	c.Error = errors.Wrap(err, "searching for file")
	rw.WriteHeader(http.StatusNotFound)
	return
}

func (c *Context) DeleteDocRoute(rw web.ResponseWriter, req *web.Request){
	userLogin, err := req.Cookie("login")
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing login")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	docId := req.PathParams["id"]

	_, ok := cache[docId]
	if (ok) {
		delete(cache, docId)
	}

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

		_, err = os.Stat("./UserFiles/" + userLogin.Value + "/" + doc.Name)
		if (os.IsNotExist(err)) {
			err = errors.New("there is no such a file")
			c.Error = errors.Wrap(err, "trying to delete file, which doesn't exist")
			rw.WriteHeader(http.StatusBadRequest)
		} else {
			err = os.Remove("./UserFiles/" + userLogin.Value + "/" + doc.Name)
			if (err != nil) {
				c.Error = errors.Wrap(err, "deleting file ./UserFiles/" + userLogin.Value + "/" + doc.Name)
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
func (c *Context) PostRegisterRoute(rw web.ResponseWriter, req *web.Request){
	var regForm	RegisterForm

	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&regForm)
	if (err != nil) {
		c.Error = errors.Wrap(err, "parsing register form")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	err = VerifyRegisterParameters(regForm.Login, false)
	if (err != nil) {
		c.Error = errors.Wrap(err, "registering with bad login")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	err = VerifyRegisterParameters(regForm.Password, true)
	if (err != nil) {
		c.Error = errors.Wrap(err, "registering with bad password")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	err = os.MkdirAll("./UserFiles/" + regForm.Login + "/", os.ModePerm)
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
	rw.Header().Set("Location", "auth/")
	rw.WriteHeader(http.StatusOK)
	c.Reply(rw, req, reply)
}

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
