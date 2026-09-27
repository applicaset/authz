package main

import (
	authzapp "github.com/buildset/buildset/authz/app"
	"github.com/buildset/buildset/pkg/serve"
)

func main() { serve.Main(authzapp.Run) }
