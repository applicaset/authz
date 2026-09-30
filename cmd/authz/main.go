package main

import (
	authzapp "github.com/applicaset/buildset/authz/app"
	"github.com/applicaset/buildset/pkg/serve"
)

func main() { serve.Main(authzapp.Run) }
