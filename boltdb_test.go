package boltdb

//Credits: https://github.com/felipeweb/osin-mysql

import (
	"log"
	"math/rand"
	"os"
	"path"
	"testing"
	"time"

	"github.com/RangelReale/osin"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dcalandria/osin-boltdb/storage"
)

var store storage.Storage
var userDataMock = "bar"

const alphabet = "abcdef0123456789"

func init() {
	rand.Seed(time.Now().Unix())
}

func randomFilename(l int) string {
	name := make([]byte, l)
	rand.Read(name)
	for i, b := range name {
		name[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(name)
}

func TestMain(m *testing.M) {
	var err error
	filename := path.Join(os.TempDir(), randomFilename(10)+".db")
	store, err = New(filename)
	if err != nil {
		log.Fatalf("Could not open database: %v", err)
	}

	retCode := m.Run()

	store.Close()
	os.Remove(filename)

	os.Exit(retCode)
}

func TestClientOperations(t *testing.T) {
	create := &osin.DefaultClient{Id: "1", Secret: "secret", RedirectUri: "http://localhost/", UserData: ""}
	createClient(t, store, create)
	getClient(t, store, create)
}

func TestAuthorizeOperations(t *testing.T) {
	client := &osin.DefaultClient{Id: "2", Secret: "secret", RedirectUri: "http://localhost/", UserData: ""}
	createClient(t, store, client)

	for _, authorize := range []*osin.AuthorizeData{
		{
			Client:      client,
			Code:        uuid.New(),
			ExpiresIn:   int32(600),
			Scope:       "scope",
			RedirectUri: "http://localhost/",
			State:       "state",
			CreatedAt:   time.Now().Round(time.Second),
			UserData:    userDataMock,
		},
	} {
		// Test save
		require.Nil(t, store.SaveAuthorize(authorize))

		// Test fetch
		_, err := store.LoadAuthorize(authorize.Code)
		require.Nil(t, err)
		require.Equal(t, authorize.CreatedAt.Unix(), authorize.CreatedAt.Unix())

		// Test remove
		require.Nil(t, store.RemoveAuthorize(authorize.Code))
		_, err = store.LoadAuthorize(authorize.Code)
		require.NotNil(t, err)
	}

}

func TestStoreFailsOnInvalidUserData(t *testing.T) {
	client := &osin.DefaultClient{Id: "3", Secret: "secret", RedirectUri: "http://localhost/", UserData: ""}
	authorize := &osin.AuthorizeData{
		Client:      client,
		Code:        uuid.New(),
		ExpiresIn:   int32(60),
		Scope:       "scope",
		RedirectUri: "http://localhost/",
		State:       "state",
		CreatedAt:   time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		UserData:    struct{ foo string }{"bar"},
	}
	access := &osin.AccessData{
		Client:        client,
		AuthorizeData: authorize,
		AccessData:    nil,
		AccessToken:   uuid.New(),
		RefreshToken:  uuid.New(),
		ExpiresIn:     int32(60),
		Scope:         "scope",
		RedirectUri:   "https://localhost/",
		CreatedAt:     time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		UserData:      struct{ foo string }{"bar"},
	}
	assert.Nil(t, store.SaveAuthorize(authorize))
	assert.Nil(t, store.SaveAccess(access))
}

func TestAccessOperations(t *testing.T) {
	client := &osin.DefaultClient{Id: "3", Secret: "secret", RedirectUri: "http://localhost/", UserData: ""}
	authorize := &osin.AuthorizeData{
		Client:      client,
		Code:        uuid.New(),
		ExpiresIn:   int32(60),
		Scope:       "scope",
		RedirectUri: "http://localhost/",
		State:       "state",
		CreatedAt:   time.Now().Round(time.Second),
		UserData:    userDataMock,
	}
	nestedAccess := &osin.AccessData{
		Client:        client,
		AuthorizeData: authorize,
		AccessData:    nil,
		AccessToken:   uuid.New(),
		RefreshToken:  uuid.New(),
		ExpiresIn:     int32(60),
		Scope:         "scope",
		RedirectUri:   "https://localhost/",
		CreatedAt:     time.Now().Round(time.Second),
		UserData:      userDataMock,
	}
	access := &osin.AccessData{
		Client:        client,
		AuthorizeData: authorize,
		AccessData:    nestedAccess,
		AccessToken:   uuid.New(),
		RefreshToken:  uuid.New(),
		ExpiresIn:     int32(60),
		Scope:         "scope",
		RedirectUri:   "https://localhost/",
		CreatedAt:     time.Now().Round(time.Second),
		UserData:      userDataMock,
	}

	require.Nil(t, store.SaveAuthorize(authorize))
	require.Nil(t, store.SaveAccess(nestedAccess))
	require.Nil(t, store.SaveAccess(access))

	_, err := store.LoadAccess(access.AccessToken)
	require.NotNil(t, err)

	require.Nil(t, store.RemoveAuthorize(authorize.Code))
	_, err = store.LoadAccess(access.AccessToken)
	require.NotNil(t, err)

	require.Nil(t, store.RemoveAccess(nestedAccess.AccessToken))
	_, err = store.LoadAccess(access.AccessToken)
	require.NotNil(t, err)

	require.Nil(t, store.RemoveAccess(access.AccessToken))
	_, err = store.LoadAccess(access.AccessToken)
	require.NotNil(t, err)

	require.Nil(t, store.RemoveAuthorize(authorize.Code))
}

func TestRefreshOperations(t *testing.T) {
	client := &osin.DefaultClient{Id: "4", Secret: "secret", RedirectUri: "http://localhost/", UserData: ""}
	type test struct {
		access *osin.AccessData
	}

	for k, c := range []*test{
		{
			access: &osin.AccessData{
				Client: client,
				AuthorizeData: &osin.AuthorizeData{
					Client:      client,
					Code:        uuid.New(),
					ExpiresIn:   int32(60),
					Scope:       "scope",
					RedirectUri: "http://localhost/",
					State:       "state",
					CreatedAt:   time.Now().Round(time.Second),
					UserData:    userDataMock,
				},
				AccessData:   nil,
				AccessToken:  uuid.New(),
				RefreshToken: uuid.New(),
				ExpiresIn:    int32(60),
				Scope:        "scope",
				RedirectUri:  "https://localhost/",
				CreatedAt:    time.Now().Round(time.Second),
				UserData:     userDataMock,
			},
		},
	} {

		_, err := store.LoadRefresh(c.access.RefreshToken)
		require.NotNil(t, err)

		require.Nil(t, store.RemoveRefresh(c.access.RefreshToken))
		_, err = store.LoadRefresh(c.access.RefreshToken)

		require.NotNil(t, err, "Case %d", k)
		require.Nil(t, store.RemoveAccess(c.access.AccessToken), "Case %d", k)
		require.Nil(t, store.SaveAccess(c.access), "Case %d", k)

		_, err = store.LoadRefresh(c.access.RefreshToken)
		require.NotNil(t, err, "Case %d", k)

		require.Nil(t, store.RemoveAccess(c.access.AccessToken), "Case %d", k)
		_, err = store.LoadRefresh(c.access.RefreshToken)
		require.NotNil(t, err, "Case %d", k)

	}
}

func getClient(t *testing.T, store storage.Storage, set osin.Client) {
	client, err := store.GetClient(set.GetId())
	require.Nil(t, err)
	require.EqualValues(t, set, client)
}

func createClient(t *testing.T, store storage.Storage, set osin.Client) {
	require.Nil(t, store.CreateClient(set))
}
