package identutil

import (
	_ "embed"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/halliday/go-module"
)

//go:embed messages.csv
var messages string

var l, e, Module = module.New("identutil", messages)

type UserId uuid.UUID

func (id *UserId) UnmarshalJSON(data []byte) (err error) {
	var str string
	if err = json.Unmarshal(data, &str); err != nil {
		return err
	}
	uid, err := uuid.Parse(str)
	if err != nil {
		return err
	}
	*id = UserId(uid)
	return nil
}

func (id UserId) String() string {
	return uuid.UUID(id).String()
}

func (id UserId) MarshalJSON() (data []byte, err error) {
	return json.Marshal(id.String())
}
