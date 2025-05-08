package pe16

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const COMPRESSED_EXE_FILE_PATH = "files/compressed_exe"
const UNCOMPRESSED_EXE_FILE_PATH = "files/uncompressed_exe"

// Function to parse an EXE file, given the filename as well as the testing_handle
// for any load or parsing assertions that may come up
func parseEXE(filename string, testing_handle *testing.T) PE16 {
	exe_bytes, _error := os.ReadFile(filename)

	if nil != _error {
		assert.Fail(testing_handle, "Failed to read test binary")
	}

	// Create our parser object
	parser := PE16Parser{}
	
	// Set our input data and parse our PE16 file
	pe16Information, _error := parser.SetInputData(exe_bytes).Parse()

	// Make sure there was no error
	assert.Nil(testing_handle, _error)
	return pe16Information
}

func TestHeaderRead(testing_handle *testing.T) {
	pe16Information := parseEXE(UNCOMPRESSED_EXE_FILE_PATH, testing_handle)

	// Make sure our magic number is correct
	assert.Equal(testing_handle, uint16(0x5A4D), pe16Information.Header.MagicNumber)
	// Make sure the bytes of our last page are correct
	assert.Equal(testing_handle, uint16(0x1F0), pe16Information.Header.BytesOfLastPage)
	// Make sure the number of pages in the file is correct
	assert.Equal(testing_handle, uint16(0xD), pe16Information.Header.PagesInFile)
	// Make sure the number of relocations is correct
	assert.Equal(testing_handle, uint16(1), pe16Information.Header.NumberOfRelocations)
	// Make sure the size of the header in paragraphs is correct
	assert.Equal(testing_handle, uint16(0x20), pe16Information.Header.SizeOfHeaderInParagraphs)
	// Make sure the minimum extra paragraphs are correct
	assert.Equal(testing_handle, uint16(0), pe16Information.Header.MinimumExtraParagraphs)
	// Make sure the maximum extra paragraphs are correct
	assert.Equal(testing_handle, uint16(0xFFFF), pe16Information.Header.MaximumExtraParagraphs)
	// Make sure that the initial relative Stack Segment (SS) is correct
	assert.Equal(testing_handle, uint16(0x177), pe16Information.Header.InitialSS)
	// Make sure that the initial Stack Pointer (SP) is correct
	assert.Equal(testing_handle, uint16(0x80), pe16Information.Header.InitialSP)
	// Make sure that the checksum is correct
	assert.Equal(testing_handle, uint16(0), pe16Information.Header.Checksum)
	// Make sure that the initial Instruction Pointer (IP) is correct
	assert.Equal(testing_handle, uint16(0), pe16Information.Header.InitialIP)
	// Make sure that the initial Code Segment (CS) is correct
	assert.Equal(testing_handle, uint16(0), pe16Information.Header.InitialCS)
	// Make sure that the file address of the relocation table is correct
	assert.Equal(testing_handle, uint16(0x3E), pe16Information.Header.FileAddressOfRelocationTable)
	// Make sure that our overlay number is correct
	assert.Equal(testing_handle, uint16(0), pe16Information.Header.OverlayNumber)
}

func TestRelocationTableRead(testing_handle *testing.T) {
	pe16Information := parseEXE(UNCOMPRESSED_EXE_FILE_PATH, testing_handle)
	// Make sure that our relocation table slice is 1 "entry" long
	assert.Equal(testing_handle, 1, len(pe16Information.RelocationTable))
	// Get our relocation table entry

	relocationTableEntry := pe16Information.RelocationTable[0]

	// Make sure our segment is correct
	assert.Equal(testing_handle, uint16(0x0001), relocationTableEntry.Segment)
	// Make sure our offset is correct
	assert.Equal(testing_handle, uint16(0x0000), relocationTableEntry.Offset)
}

func TestExtraHeaderDataRead(testing_handle *testing.T) {
	pe16Information := parseEXE(COMPRESSED_EXE_FILE_PATH, testing_handle)

	// Make sure that our extra data is correct; in this case, it is the LZEXE
	// signature, which LZEXE inserts as extra data for file identification

	assert.Equal(testing_handle, byte(0x4C), pe16Information.ExtraHeaderData[0])
	assert.Equal(testing_handle, byte(0x5A), pe16Information.ExtraHeaderData[1])
	assert.Equal(testing_handle, byte(0x39), pe16Information.ExtraHeaderData[2])
	assert.Equal(testing_handle, byte(0x31), pe16Information.ExtraHeaderData[3])
}

func TestExecutableDataRead(testing_handle *testing.T) {

}
