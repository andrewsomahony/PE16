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
	// Our extra header data
	// This is here because our header may give a length that is more
	// than the standard PE16 header length plus the relocation table
	// size, for things like a signature or something, so we capture
	// that here.
	ExtraHeaderData []byte
	// Our relocation table
	RelocationTable []PE16RelocationEntry
	// Our Executable Data
	ExecutableData []byte
}
