package main

import (
	"backend-go/config"
	"backend-go/routes"
)

func main() {
	config.ConnectDB()

	router := routes.SetupRouter()
	router.Run(":5000")
}
