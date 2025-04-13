package pe16

type PE16Header struct {
	MagicNumber uint16

	BytesOfLastPage uint16
	PagesInFile uint16

	NumberOfRelocations uint16

	SizeOfHeaderInParagraphs uint16

	MinimumExtraParagraphs uint16
	MaximumExtraParagraphs uint16

	InitialSS uint16
	InitialSP uint16

	Checksum uint16

	InitialIP uint16
	InitialCS uint16

	FileAddressOfRelocationTable uint16

	OverlayNumber uint16
}

type PE16RelocationEntry struct {
	Segment uint16
	Offset uint16
}

type PE16 struct {
	Header PE16Header
	// All our binary data, including relocations
	// We have it this way because some old-school programs would
	// inject data into the relocation table area, that was meant to
	// serve as an identifier, so with this, we can grab it how we wish
	Data []byte
	// Our relocation table
	RelocationTable []PE16RelocationEntry
	// Our Executable Data
	ExecutableData []byte
}
