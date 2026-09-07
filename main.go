package main

import (
	"fmt"
)

func main() {
	host := "127.0.0.1"
	port := 5432
	database := "postgres"
	username := "postgres"
	password := ""

	pgconn, err := NewConnection(host, port, database, username, password)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	defer pgconn.Close()

	// 2. Send:
	//
	//     SELECT * FROM users
	//
	// using PostgreSQL's Simple Query protocol.
	if err := pgconn.sendQuery("SELECT 2"); err != nil {
		panic(err)
	}

	// 3. Read the server responses.
	if err := pgconn.readResults(); err != nil {
		panic(err)
	}
}
