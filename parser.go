package pe16

import (
	"bytes"
	"encoding/binary"
)

type PE16Parser struct {
	inputData []byte
}

func (parser *PE16Parser) SetInputData(inputData []byte) *PE16Parser {
	parser.inputData = inputData
	return parser
}

func (parser *PE16Parser) Parse() (PE16, error) {
	var pe16 PE16

	reader := bytes.NewReader(parser.inputData)

	// Read our header
	_error := binary.Read(reader, binary.LittleEndian, &pe16.Header)

	if nil == _error {
		// If we read our header ok, then we can proceed to read our data
	}

	return pe16, _error
}
