package factordbapi

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

const ENDPOINT = "http://factordb.com/api"

type FactorDB struct {
	Number string
	Result FactorDBResponse
}

func (f *FactorDB) Empty() bool {
	if f.Result.Status == "" {
		return true
	}
	return false
}

func (f *FactorDB) Connect() error {
	values := url.Values{}
	values.Add("query", fmt.Sprintf("%s", f.Number))
	resp, err := http.Get(fmt.Sprintf("%s?%s", ENDPOINT, values.Encode()))
	if err != nil {
		return errors.New("cannot connect" + ENDPOINT)
	}

	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.New("Empty Body")
	}

	response, err := ConvertToFactorDB(b)
	if err != nil {
		return errors.New("Cannot converting data")
	}

	f.Result = response
	return nil
}

func (f *FactorDB) GetId() (string, error) {
	if f.Empty() {
		return "", errors.New("Empty Result")
	}
	return f.Result.Id, nil
}

func (f *FactorDB) GetStatus() (string, error) {
	if f.Empty() {
		return "", errors.New("Empty Result")
	}
	return f.Result.Status, nil
}

func (f *FactorDB) GetFactorList() ([]Factor, error) {
	if f.Empty() {
		return []Factor{}, errors.New("Empty Result")
	}
	return f.Result.Factors, nil
}

func GetFactors(c string) ([]Factor, error) {
	n := c

	f := FactorDB{Number: n}
	if err := f.Connect(); err != nil {
		log.Fatal("Connection Error")
	}

	factors, _ := f.GetFactorList()
	return factors, nil
}
