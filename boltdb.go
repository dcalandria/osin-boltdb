package boltdb

import (
	"time"

	"github.com/RangelReale/osin"
	"github.com/boltdb/bolt"
	"github.com/gogo/protobuf/proto"

	"github.com/dcalandria/osin-boltdb/model"
	"github.com/dcalandria/osin-boltdb/storage"
)

var (
	clientBucket    = []byte("client")
	authorizeBucket = []byte("authorize")
	accessBucket    = []byte("access")
	refreshBucket   = []byte("refresh")

	allBuckets = [][]byte{
		clientBucket,
		authorizeBucket,
		accessBucket,
		refreshBucket,
	}
)

type Storage struct {
	db *bolt.DB
}

func (s *Storage) get(tx *bolt.Tx, bucket []byte, key []byte, dest interface{}) (err error) {
	value := tx.Bucket(bucket).Get(key)
	if value == nil {
		err = osin.ErrNotFound
	} else {
		switch dest := dest.(type) {
		case proto.Message:
			err = proto.Unmarshal(value, dest)
		case *[]byte:
			*dest = value
		default:
			panic("only proto.Message and *[]byte dest are supported")
		}
	}
	return
}

type writeFunc func(tx *bolt.Tx, bucket []byte, key []byte, value interface{}) error

func (s *Storage) insert(tx *bolt.Tx, bucket []byte, key []byte, value interface{}) error {
	v := tx.Bucket(bucket).Get(key)
	if v != nil {
		return storage.ErrAlreadyExists
	}
	return s.put(tx, bucket, key, value)
}

func (s *Storage) update(tx *bolt.Tx, bucket []byte, key []byte, value interface{}) error {
	v := tx.Bucket(bucket).Get(key)
	if v == nil {
		return osin.ErrNotFound
	}
	return s.put(tx, bucket, key, value)
}

func (s *Storage) put(tx *bolt.Tx, bucket []byte, key []byte, value interface{}) error {
	var data []byte
	if value != nil {
		switch value := value.(type) {
		case []byte:
			data = value
		case proto.Message:
			data, _ = proto.Marshal(value)
		}
	}
	return tx.Bucket(bucket).Put(key, data)
}

func (s *Storage) delete(tx *bolt.Tx, bucket []byte, key []byte) error {
	return tx.Bucket(bucket).Delete(key)
}

func (s *Storage) deleteClient(tx *bolt.Tx, id string) error {
	return s.delete(tx, clientBucket, []byte(id))
}

func (s *Storage) putClient(tx *bolt.Tx, client osin.Client, f writeFunc) error {
	userdata, err := model.DefaultUserDataCodec.EncodeUserData(client.GetUserData())
	if err != nil {
		//TODO: log?
	}
	msg := model.Client{
		Id:          client.GetId(),
		Secret:      client.GetSecret(),
		RedirectUri: client.GetRedirectUri(),
		UserData:    userdata,
	}
	return f(tx, clientBucket, []byte(msg.Id), &msg)
}

func (s *Storage) getClient(tx *bolt.Tx, id string) (osin.Client, error) {
	msg := &model.Client{}
	err := s.get(tx, clientBucket, []byte(id), msg)
	if err != nil {
		return nil, err
	}
	userdata, _ := model.DefaultUserDataCodec.DecodeUserData(msg.UserData)
	return &osin.DefaultClient{
		Id:          msg.Id,
		Secret:      msg.Secret,
		RedirectUri: msg.RedirectUri,
		UserData:    userdata,
	}, nil
}

func (s *Storage) deleteAuthorize(tx *bolt.Tx, code string) error {
	return s.delete(tx, authorizeBucket, []byte(code))
}

func (s *Storage) putAuthorize(tx *bolt.Tx, authorize *osin.AuthorizeData, f writeFunc) error {
	createdAt, _ := authorize.CreatedAt.MarshalBinary()
	userdata, _ := model.DefaultUserDataCodec.EncodeUserData(authorize.UserData)
	msg := model.AuthorizeData{
		ClientId:            authorize.Client.GetId(),
		Code:                authorize.Code,
		ExpiresIn:           authorize.ExpiresIn,
		Scope:               authorize.Scope,
		RedirectUri:         authorize.RedirectUri,
		State:               authorize.State,
		CreatedAt:           createdAt,
		UserData:            userdata,
		CodeChallenge:       authorize.CodeChallenge,
		CodeChallengeMethod: authorize.CodeChallengeMethod,
	}
	return f(tx, authorizeBucket, []byte(msg.Code), &msg)
}

func (s *Storage) getAuthorize(tx *bolt.Tx, code string) (*osin.AuthorizeData, error) {
	msg := &model.AuthorizeData{}
	err := s.get(tx, authorizeBucket, []byte(code), msg)
	if err != nil {
		return nil, err
	}

	client, err := s.getClient(tx, msg.ClientId)
	if err != nil {
		return nil, err
	}

	userdata, _ := model.DefaultUserDataCodec.DecodeUserData(msg.UserData)
	createdAt := time.Time{}
	createdAt.UnmarshalBinary(msg.CreatedAt)

	return &osin.AuthorizeData{
		Client:              client,
		Code:                msg.Code,
		ExpiresIn:           msg.ExpiresIn,
		Scope:               msg.Scope,
		RedirectUri:         msg.RedirectUri,
		State:               msg.State,
		CreatedAt:           createdAt,
		UserData:            userdata,
		CodeChallenge:       msg.CodeChallenge,
		CodeChallengeMethod: msg.CodeChallengeMethod,
	}, nil
}

func (s *Storage) deleteAccess(tx *bolt.Tx, token string) error {
	return s.delete(tx, accessBucket, []byte(token))
}

func (s *Storage) putAccess(tx *bolt.Tx, access *osin.AccessData, f writeFunc) error {
	createdAt, _ := access.CreatedAt.MarshalBinary()
	userdata, _ := model.DefaultUserDataCodec.EncodeUserData(access.UserData)
	msg := model.AccessData{
		ClientId:     access.Client.GetId(),
		AccessToken:  access.AccessToken,
		RefreshToken: access.RefreshToken,
		ExpiresIn:    access.ExpiresIn,
		Scope:        access.Scope,
		RedirectUri:  access.RedirectUri,
		CreatedAt:    createdAt,
		UserData:     userdata,
	}

	if access.AuthorizeData != nil {
		msg.AuthorizeCode = access.AuthorizeData.Code
	}

	if access.AccessData != nil {
		msg.PrevAccessToken = access.AccessData.AccessToken
	}

	return f(tx, accessBucket, []byte(msg.AccessToken), &msg)
}

func (s *Storage) getAccess(tx *bolt.Tx, token string) (*osin.AccessData, error) {
	msg := &model.AccessData{}
	err := s.get(tx, clientBucket, []byte(token), msg)
	if err != nil {
		return nil, err
	}

	client, err := s.getClient(tx, msg.ClientId)
	if err != nil {
		return nil, err
	}

	authorize, _ := s.getAuthorize(tx, msg.AuthorizeCode)
	access, _ := s.getAccess(tx, msg.PrevAccessToken)
	createdAt := time.Time{}
	createdAt.UnmarshalBinary(msg.CreatedAt)
	userdata, _ := model.DefaultUserDataCodec.DecodeUserData(msg.UserData)

	return &osin.AccessData{
		Client:        client,
		AuthorizeData: authorize,
		AccessData:    access,
		AccessToken:   msg.AccessToken,
		RefreshToken:  msg.RefreshToken,
		ExpiresIn:     msg.ExpiresIn,
		Scope:         msg.Scope,
		RedirectUri:   msg.RedirectUri,
		CreatedAt:     createdAt,
		UserData:      userdata,
	}, nil
}

func (s *Storage) putRefresh(tx *bolt.Tx, access *osin.AccessData, f writeFunc) error {
	if access.RefreshToken == "" {
		return nil
	}
	return f(tx, refreshBucket, []byte(access.RefreshToken), []byte(access.AccessToken))
}

func (s *Storage) deleteRefresh(tx *bolt.Tx, token string) error {
	return s.delete(tx, refreshBucket, []byte(token))
}

func (s *Storage) getRefresh(tx *bolt.Tx, token string) (*osin.AccessData, error) {
	var accessToken []byte
	err := s.get(tx, refreshBucket, []byte(token), &accessToken)
	if err != nil {
		return nil, err
	}
	return s.getAccess(tx, string(accessToken))
}

func (s *Storage) Clone() osin.Storage {
	return s
}

// Close the resources the Storage potentially holds (using Clone for example)
func (s *Storage) Close() {
	s.db.Close()
}

func (s *Storage) CreateClient(client osin.Client) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return s.putClient(tx, client, s.insert)
	})
}

func (s *Storage) UpdateClient(client osin.Client) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return s.putClient(tx, client, s.update)
	})
}

func (s *Storage) RemoveClient(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return s.deleteClient(tx, id)
	})
}

// GetClient loads the client by id (client_id)
func (s *Storage) GetClient(id string) (osin.Client, error) {
	tx, _ := s.db.Begin(false)
	defer tx.Rollback()
	return s.getClient(tx, id)
}

// SaveAuthorize saves authorize data.
func (s *Storage) SaveAuthorize(authorize *osin.AuthorizeData) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return s.putAuthorize(tx, authorize, s.insert)
	})
}

// LoadAuthorize looks up AuthorizeData by a code.
// Client information MUST be loaded together.
// Optionally can return error if expired.
func (s *Storage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	tx, _ := s.db.Begin(false)
	defer tx.Rollback()
	return s.getAuthorize(tx, code)
}

// RemoveAuthorize revokes or deletes the authorization code.
func (s *Storage) RemoveAuthorize(code string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return s.deleteAuthorize(tx, code)
	})
}

// SaveAccess writes AccessData.
// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
func (s *Storage) SaveAccess(access *osin.AccessData) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		err := s.putAccess(tx, access, s.insert)
		if err != nil {
			return err
		}
		return s.putRefresh(tx, access, s.insert)
	})
}

// LoadAccess retrieves access data by token. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *Storage) LoadAccess(token string) (*osin.AccessData, error) {
	tx, _ := s.db.Begin(false)
	defer tx.Rollback()
	return s.getAccess(tx, token)
}

// RemoveAccess revokes or deletes an AccessData.
func (s *Storage) RemoveAccess(token string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return s.deleteAccess(tx, token)
	})
}

// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
// Optionally can return error if expired.
func (s *Storage) LoadRefresh(token string) (*osin.AccessData, error) {
	tx, _ := s.db.Begin(false)
	defer tx.Rollback()
	return s.getRefresh(tx, token)
}

// RemoveRefresh revokes or deletes refresh AccessData.
func (s *Storage) RemoveRefresh(token string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return s.deleteRefresh(tx, token)
	})
}

// Initializes the database
func (s *Storage) InitDB() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range allBuckets {
			_, err := tx.CreateBucketIfNotExists(bucket)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func New(db *bolt.DB) *Storage {
	return &Storage{
		db: db,
	}
}
