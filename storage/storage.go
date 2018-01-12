package storage

import (
	"errors"

	"github.com/RangelReale/osin"
)

var ErrAlreadyExists = errors.New("already exists")

type Storage interface {
	osin.Storage
	CreateClient(client osin.Client) error
	UpdateClient(client osin.Client) error
	RemoveClient(id string) error
}
