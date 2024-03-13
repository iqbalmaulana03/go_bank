package main

import "log"

func main() {

	db, err := NewPostgresStore()
	if err != nil {
		log.Fatal(err)
	}

	if err := db.init(); err != nil {
		log.Fatal(err)
	}

	server := NewApiSever(":3000", db)
	server.Run()
}
