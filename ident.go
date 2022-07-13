package ident

import (
	_ "embed"

	"github.com/halliday/go-module"
	"github.com/halliday/go-openid"
)

//go:embed messages.csv
var messages string

var l, e, Module = module.New("ident", messages)

type Scopes = openid.Scopes

func NewScopes(str string) Scopes {
	return openid.NewScopes(str)
}
