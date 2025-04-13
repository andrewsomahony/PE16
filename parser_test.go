package pe16

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeaderRead(testing_handle *testing.T) {
	// !!! Temporary header bytes, load from a file??
	test_bytes := []byte {0x4d, 0x5a, 0x2c, 0x01,
											  0x0a, 0x00, 0x00, 0x00,
												0x02, 0x00, 0x95, 0x00,
												0xff, 0xff, 0xa7, 0x01,
												0x80, 0x00, 0x00, 0x00,
												0x0e, 0x00, 0x1b, 0x01,
												0x1c, 0x00, 0x00, 0x00}

	// Create our parser object
	parser := PE16Parser{}
	
	// Set our input data and parse our PE16 file
	pe16Information, _error := parser.SetInputData(test_bytes).Parse()

	assert.Nil(testing_handle, _error)
	// Make sure our magic number is correct
	assert.Equal(testing_handle, uint16(0x5A4D), pe16Information.Header.MagicNumber)
}
