package main

import(
	"fmt"
	"log"
	"net/http"
	"strconv"
	"database/sql"
	"encoding/json"
	"sync"
	"errors"

	"github.com/gocraft/web"
	_ "github.com/lib/pq"
)

type Doc struct {
	Id	int	`json:"id"`
	Name	string	`json:"name"`
	Content string	`json:"content"`
}

type Docs struct {
	DocsList	[]*Doc	`json:"docs,omitempty"`
}

type ReplyError struct {
	code	int	`json:"code"`
	text	string	`json:"text"`
}

type Response struct {
	//TODO(Alidar) Fill this
}

type ReplyData struct {
	//TODO(Alidar) Fill this
}

type ReplyModel struct {
	Err	ReplyError	`json:"error"`
	Res	Response	`json:"responce"`
	Data	ReplyData	`json:"data"`
}

type Context struct {
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
		return data, errors.New("No such a value in cache")
	}
	mutex.Unlock()
	return data, nil
}

func main() {
	var err error
	db, err = sql.Open("postgres", "postgres://alidar:1@localhost/cachingserverdb");
	if (err != nil){
		log.Println("[ERR] Opening DB: ", err)
		return
	}
	defer db.Close()

	router := web.New(Context{}).Middleware(web.LoggerMiddleware)
	router.Get("/", (*Context).RootRoute)
	router.Get("/docs", (*Context).GetDocsRoute)
	router.Get("/docs/:id", (*Context).GetDocByIdRoute)
	http.ListenAndServe("localhost:8000", router)
}

func (c *Context) RootRoute(rw web.ResponseWriter, req *web.Request){
	fmt.Fprint(rw, "Hi there")
}

func (c *Context) GetDocsRoute(rw web.ResponseWriter, req *web.Request){
	limit := req.URL.Query().Get("limit")
	key := req.URL.Query().Get("key")
	value := req.URL.Query().Get("value")

	var countOfDocs int
	var err error
	if (limit != "") {
		countOfDocs, err = strconv.Atoi(limit)
		if err != nil{
			countOfDocs = 0
		}
	}

	if (key != "") {
		if (key != "name" || key != "id" || key != "created") {
			key = "name"
		}
	} else {
		key = "name"
	}

	if (value != "") {
		if (value != "asc" || value != "desc") {
			value = "asc"
		}
	} else {
		value = "asc"
	}

	if (cacheIsRelevant){
		//TODO(Alidar): limit number of docs responded
		marshaledCache, err := json.Marshal(cache)
		if (err != nil) {
			log.Println("[ERR] GET /doc while marshaling cache")
			SetCacheIrrelevant()
			return
		}
		rw.Write([]byte(marshaledCache))
	} else{
		var result *sql.Rows
		if (countOfDocs == 0){
			result, err = db.Query(`
				SELECT id, name, content 
				FROM docs
				ORDER BY ` +  key + ` ` +  value)

		} else {
			result, err = db.Query(`
				SELECT id, name, content 
				FROM docs 
				ORDER BY ` +  key + ` ` +  value + `
				LIMIT $1`, countOfDocs)
		}

		if (err != nil){
			log.Println("[ERR] GET /docs while querying: ", err)
			return
		}
		defer result.Close()

		docs := new(Docs)
		for result.Next(){
			doc := new(Doc)
			err := result.Scan(&doc.Id, &doc.Name, &doc.Content)
			if (err != nil){
				log.Println("[ERR] GET /doc while scanning result: ", err)
				return
			}
			docs.DocsList = append(docs.DocsList, doc)

			WriteToCache(strconv.Itoa(doc.Id), *doc)
		}

		if err = result.Err(); err != nil {
			log.Println("[ERR] GET /doc after delving in result: ", err)
			SetCacheIrrelevant()
			return
		}
		SetCacheRelevant()

		response, err := json.Marshal(docs)
		if (err != nil) {
			log.Println("[ERR] GET /doc while marshaling docs")
			SetCacheIrrelevant()
			return
		}
		rw.Write(response)
	}

}

func (c *Context) GetDocByIdRoute(rw web.ResponseWriter, req *web.Request){
	//TODO(Alidar): id needs to be validated
	var docId = req.PathParams["id"]

	if (cacheIsRelevant) {
		marshaledCache, err := json.Marshal(cache[docId])
		if (err != nil) {
			log.Println("[ERR] GET /doc while marshaling cache")
			SetCacheIrrelevant()
			return
		}
		fmt.Println("11")
		rw.Write([]byte(marshaledCache))
	} else {
		//TOFIGUREOUT(Alidar): Should I retrieve ALL data from db in order to update cache??
		result, err := db.Query("SELECT id, name, content FROM docs WHERE id=$1", docId)
		if (err != nil){
			log.Println("[ERR] GET /doc:id while querying: ", err)
			return
		}
		defer result.Close()

		doc := new(Doc)
		for result.Next(){
			err := result.Scan(&doc.Id, &doc.Name, &doc.Content)
			if (err != nil){
				log.Println("[ERR] GET /doc:id while scanning result: ", err)
				return
			}
			break
		}

		if err = result.Err(); err != nil {
			log.Println(err)
		}
		response, err := json.Marshal(doc)
		if (err != nil) {
			log.Println("[ERR] GET /doc/:id while marshaling result: ", err)
			return
		}

		rw.Write(response)

	}

}


