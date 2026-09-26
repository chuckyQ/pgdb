# pgdb
Lightweight library for interacting with Postgres using a pure Golang implementation

## Example

```go
package main

import (
	"fmt"

	"github.com/chuckyQ/pgdb"
)

func main() {

	conn, err := pgdb.Connect("127.0.0.1", 5432, "postgres", "postgres", "mypassword")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	nulls, data, columns, types, err := conn.Exec("SELECT * FROM users")

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(columns)
	fmt.Println(types)

	for i, row := range data {
		fmt.Println(nulls[i])
		fmt.Println(row)
	}

}

```
