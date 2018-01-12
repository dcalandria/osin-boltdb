package model

import (
	"encoding/binary"
	"errors"
	"math"
	"reflect"

	"github.com/gogo/protobuf/proto"
)

var ErrWrongValue = errors.New("wrong value")

type UserDataCodec interface {
	EncodeUserData(interface{}) (*UserData, error)
	DecodeUserData(*UserData) (interface{}, error)
}

type defaultCodec struct{}

func (c defaultCodec) encodeUsingReflect(rv reflect.Value) (data []byte, dataType UserData_Type) {
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		data = make([]byte, binary.MaxVarintLen64)
		n := binary.PutVarint(data, rv.Int())
		data, dataType = data[:n], UserData_INT
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		data = make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(data, rv.Uint())
		data, dataType = data[:n], UserData_UINT
	case reflect.Bool:
		if rv.Bool() {
			data = []byte{1}
		} else {
			data = []byte{0}
		}
		dataType = UserData_BOOL
	case reflect.String:
		data, dataType = []byte(rv.String()), UserData_STRING
	case reflect.Float32, reflect.Float64:
		f := math.Float64bits(rv.Float())
		data = make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(data, f)
		data, dataType = data[:n], UserData_FLOAT
	default:
		dataType = UserData_NIL
	}
	return
}

func (c defaultCodec) EncodeUserData(v interface{}) (*UserData, error) {
	if v == nil {
		return &UserData{
			Type: UserData_NIL,
		}, nil
	}

	var (
		data     []byte
		dataType UserData_Type
		name     string
		err      error
	)

	switch v := v.(type) {
	case proto.Message:
		data, err = proto.Marshal(v)
		if err == nil {
			dataType = UserData_PROTO
			name = proto.MessageName(v)
		}
	case []byte:
		data, dataType = v, UserData_BYTES
	case string:
		data, dataType = []byte(v), UserData_STRING
	default:
		data, dataType = c.encodeUsingReflect(reflect.ValueOf(v))
	}

	if err != nil {
		return nil, err
	}

	return &UserData{
		Type: dataType,
		Name: name,
		Data: data,
	}, nil
}

func (c defaultCodec) DecodeUserData(userData *UserData) (interface{}, error) {
	var (
		v   interface{}
		err error
	)

	switch userData.Type {
	case UserData_NIL:
	case UserData_PROTO:
		msgType := proto.MessageType(userData.Name)
		if msgType != nil {
			v = reflect.New(msgType.Elem()).Interface()
			err = proto.Unmarshal(userData.Data, v.(proto.Message))
		}
	case UserData_BYTES:
		v = userData.Data
	case UserData_STRING:
		v = string(userData.Data)
	case UserData_INT:
		var n int
		v, n = binary.Varint(userData.Data)
		if n < 0 {
			err = ErrWrongValue
		}
	case UserData_UINT:
		var n int
		v, n = binary.Uvarint(userData.Data)
		if n < 0 {
			err = ErrWrongValue
		}
	case UserData_BOOL:
		if len(userData.Data) == 0 {
			err = ErrWrongValue
		}
		v = userData.Data[0] != 0
	case UserData_FLOAT:
		f, n := binary.Uvarint(userData.Data)
		if n < 0 {
			err = ErrWrongValue
		} else {
			v = math.Float64frombits(f)
		}
	}

	if err != nil {
		return nil, err
	}
	return v, nil
}

var DefaultUserDataCodec UserDataCodec = defaultCodec{}
