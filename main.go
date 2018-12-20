package main

import(
	"fmt"
	"net/http"
	"strconv"
	"database/sql"
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
)

type Doc struct {
	Id	string	`json:"id"`
	Name	string	`json:"name"`
	Mime	string	`json:"mime"`
	Public	bool	`json:"public"`
	Created	string	`json:"created"`
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
	//TODO(Alidar) Fill this
}

type ReplyModel struct {
	Err	*ReplyError	`json:"error,omitempty"`
	Res	*Response	`json:"responce,omitempty"`
	Data	*Docs		`json:"data,omitempty"`
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

	router := web.New(Context{}).
		Middleware((*Context).Log).
		Middleware((*Context).HandleError)
	router.Get("/", (*Context).RootRoute)
	router.Get("/docs", (*Context).GetDocsRoute)
	router.Get("/docs/:id", (*Context).GetDocByIdRoute)
	router.Post("/docs", (*Context).PostDocRoute)
	http.ListenAndServe("localhost:8000", router)
}

func (c *Context) RootRoute(rw web.ResponseWriter, req *web.Request){
	fmt.Fprint(rw, "Hi there")
}

func (c *Context) PostDocRoute(rw web.ResponseWriter, req *web.Request){
	err := req.ParseMultipartForm(16777216) //16 MiB
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

	_, err = os.Stat("./UserFiles/" + fileHeader.Filename)
	if (os.IsNotExist(err)) {
		err = ioutil.WriteFile("./UserFiles/" + fileHeader.Filename, content, os.ModePerm)
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
		INSERT INTO docs (name, mime, public) 
		VALUES ($1, $2, $3);`, name, mime, public)
	if (err != nil) {
		c.Error = errors.Wrap(err, "inserting into db")
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
	limit := req.URL.Query().Get("limit")

	var countOfDocs int
	var err error
	if (limit != "") {
		countOfDocs, err = strconv.Atoi(limit)
		if err != nil{
			countOfDocs = 0
		}
	}
	if (cacheIsRelevant) {
		docs := new(Docs)
		if (countOfDocs == 0){
			for _, value := range cache {
				var doc = value
				docs.DocsList = append(docs.DocsList, &doc)
			}
		} else {
			var i = 0
			for _, value := range cache {
				var doc = value
				docs.DocsList = append(docs.DocsList, &doc)
				i++
				if (i == countOfDocs) {
					break
				}
			}
		}
		reply := &ReplyModel{
			Data: docs,
		}
		SetCacheRelevant()
		rw.WriteHeader(http.StatusOK)
		c.Reply(rw, req, reply)
	} else {
		var result *sql.Rows
		if (countOfDocs == 0){
			result, err = db.Query(`
				SELECT id, name, mime, public, created_at
				FROM docs`)

		} else {
			result, err = db.Query(`
				SELECT id, name, mime, public, created_at
				FROM docs 
				LIMIT $1`, countOfDocs)
		}

		if (err != nil){
			SetCacheIrrelevant()
			c.Error = errors.Wrap(err, "querying")
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer result.Close()

		docs := new(Docs)
		for result.Next(){
			doc := new(Doc)
			err = result.Scan(&doc.Id, &doc.Name, &doc.Mime, &doc.Public, &doc.Created)
			if (err != nil){
				SetCacheIrrelevant()
				c.Error = errors.Wrap(err, "scanning result")
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}
			docs.DocsList = append(docs.DocsList, doc)

			WriteToCache(doc.Id, *doc)
		}

		if err = result.Err(); err != nil {
			SetCacheIrrelevant()
			c.Error = errors.Wrap(err, "after delving in result")
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		SetCacheRelevant()

		reply := &ReplyModel{
			Data: docs,
		}

		rw.WriteHeader(http.StatusOK)
		c.Reply(rw, req, reply)
	}
}

func (c *Context) GetDocByIdRoute(rw web.ResponseWriter, req *web.Request){
	var docId = req.PathParams["id"]

	doc, ok := cache[docId]
	if ok {
		rw.Header().Set("Content-Type", doc.Mime)
		http.ServeFile(rw, req.Request, "./UserFiles/" + doc.Name)
	} else {
		doc := new(Doc)
		err := db.QueryRow("SELECT id, name, mime, public, created_at FROM docs WHERE id=$1", docId).
			Scan(&doc.Id, &doc.Name, &doc.Mime, &doc.Public, &doc.Created)

		if (err != nil){
			c.Error = errors.Wrap(err, "querying file")
			rw.WriteHeader(http.StatusNotFound)
			return
		}

		WriteToCache(doc.Id, *doc)

		rw.Header().Set("Content-Type", doc.Mime)
		http.ServeFile(rw, req.Request, "./UserFiles/" + doc.Name)
	}
}
