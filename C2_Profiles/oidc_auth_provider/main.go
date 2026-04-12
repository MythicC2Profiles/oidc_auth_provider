package main

import (
	"GoServices/oidc"

	"github.com/MythicMeta/MythicContainer"
)

func main() {
	oidc.Initialize()
	MythicContainer.StartAndRunForever([]MythicContainer.MythicServices{
		MythicContainer.MythicServiceAuth,
	})
}
