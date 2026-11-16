package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

var errDuplicateKey = errors.New("duplicate object key")

// checkNoDuplicateKeys fails when any object in raw repeats a key. Decoding
// into a map keeps only one of the values, so the masker would never see the
// other one, and the original bytes would carry it to the agent unmasked.
func checkNoDuplicateKeys(raw json.RawMessage) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	return walkValue(decoder)
}

func walkValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	if delim == '[' {
		return walkArray(decoder)
	}
	return walkObject(decoder)
}

func walkArray(decoder *json.Decoder) error {
	for decoder.More() {
		if err := walkValue(decoder); err != nil {
			return err
		}
	}
	_, err := decoder.Token()
	return err
}

func walkObject(decoder *json.Decoder) error {
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, _ := token.(string)
		if seen[key] {
			return errDuplicateKey
		}
		seen[key] = true
		if err := walkValue(decoder); err != nil {
			return err
		}
	}
	_, err := decoder.Token()
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
