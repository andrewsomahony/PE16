package pe16

import (
	"bytes"
	"encoding/binary"
	"io"
)

type PE16Parser struct {
	inputData []byte
}

func (parser *PE16Parser) SetInputData(inputData []byte) *PE16Parser {
	parser.inputData = inputData
	return parser
}

func (parser *PE16Parser) Parse() (PE16, error) {
	// Our default header size; anything beyond this is "extra" data
	_defaultHeaderSize := uint16(0x1C)

	// We need to declare everything here as we are using goto for
	// our error handling
	var pe16 PE16
	var actualHeaderSize uint16
	var extraHeaderSize uint16

	reader := bytes.NewReader(parser.inputData)

	// Read our header
	_error := binary.Read(reader, binary.LittleEndian, &pe16.Header)

	if nil != _error {
		goto errorHandler
	}
	// If we read our header ok, then we can proceed to read our data

	// Read our relocation table

	// Seek to our relocation table offset
	reader.Seek(int64(pe16.Header.FileAddressOfRelocationTable), io.SeekStart)

	// Allocate our relocation table array
	pe16.RelocationTable = make([]PE16RelocationEntry, pe16.Header.NumberOfRelocations)
	// Loop through our relocation table entries and read them into our relocation table
	for relocationTableIndex := uint16(0); 
			relocationTableIndex < pe16.Header.NumberOfRelocations; 
			relocationTableIndex += 1 {
		// Read our relocation table entry straight into our relocation object at the specific index
		_error = binary.Read(reader, binary.LittleEndian, &pe16.RelocationTable[relocationTableIndex])

		// If we run into an error, we have to abort
		if nil != _error {
			goto errorHandler
		}
	}

	// Calculate our actual header size
	actualHeaderSize = uint16(pe16.Header.SizeOfHeaderInParagraphs << 4)
	// Calculate our extra header size
	extraHeaderSize = actualHeaderSize - _defaultHeaderSize

	// Create our extra header data slice from our actual header offset and the size of the
	// extra header, if any
	pe16.ExtraHeaderData = parser.inputData[_defaultHeaderSize:_defaultHeaderSize + extraHeaderSize]

errorHandler:
	return pe16, _error
}
