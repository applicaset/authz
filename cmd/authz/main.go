package main

import (
	authzapp "github.com/applicaset/authz/app"
	"github.com/applicaset/pkg/serve"
)

func main() { serve.Main(authzapp.Run) }
