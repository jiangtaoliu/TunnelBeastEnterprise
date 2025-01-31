package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"reflect"

	"TunnelBeast.dhcp/auth"

	yaml "gopkg.in/yaml.v2"
)

type Configuration struct {
	ListenDev      string
	Outport        string
	Projectname    string
	User           string
	Password       string
	Projectid      string
	Projectnetwork string
	AuthProvider   auth.AuthProvider
}

type configuration struct {
	ListenDev      string
	Outport        string
	Projectname    string
	User           string
	Password       string
	Projectid      string
	Projectnetwork string
	AuthMethod     string
	AuthProvider   map[string]interface{}
}

func SetField(obj interface{}, name string, value interface{}) error {
	structValue := reflect.ValueOf(obj).Elem()
	structFieldValue := structValue.FieldByName(name)

	if !structFieldValue.IsValid() {
		return fmt.Errorf("No such field: %s in obj", name)
	}

	if !structFieldValue.CanSet() {
		return fmt.Errorf("Cannot set %s field value", name)
	}

	structFieldType := structFieldValue.Type()
	val := reflect.ValueOf(value)
	if structFieldType != val.Type() {
		return errors.New("Provided value type didn't match obj field type")
	}

	structFieldValue.Set(val)
	return nil
}

func FillStruct(target interface{}, data map[string]interface{}) error {
	for k, v := range data {
		err := SetField(target, k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func LoadConfig(filePath string, conf *Configuration) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal("Failed reading config file", err)
	}
	tmpConfig := configuration{}
	err = yaml.Unmarshal(data, &tmpConfig)
	if err != nil {
		log.Fatal("Failed reading config file", err)
	}
	conf.ListenDev = tmpConfig.ListenDev
	conf.Outport = tmpConfig.Outport
	conf.Projectname = tmpConfig.Projectname
	conf.User = tmpConfig.User
	conf.Password = tmpConfig.Password
	conf.Projectid = tmpConfig.Projectid
	conf.Projectnetwork = tmpConfig.Projectnetwork
	switch tmpConfig.AuthMethod {
	case "ldap":
		tmpProvider := auth.LDAPAuth{}
		FillStruct(&tmpProvider, tmpConfig.AuthProvider)
		conf.AuthProvider = tmpProvider
	case "test":
		tmpProvider := auth.TestAuth{}
		FillStruct(&tmpProvider, tmpConfig.AuthProvider)
		conf.AuthProvider = tmpProvider
	}
}
