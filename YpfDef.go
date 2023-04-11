package main

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"github.com/regomne/eutil/codec"
	"io"
	"sort"
)

type ypfHeader struct {
	Meta                    GenericHeader
	Num                     uint32
	ArchivedFilesHeaderSize uint32
	Unk                     [16]byte // zero?
}

type ypfEntry struct {
	NameChecksum       uint32
	FileName           string
	Type               uint8
	IsCompressed       uint8
	RawFileSize        uint32
	CompressedFileSize uint32
	Offset             uint64
	DataChecksum       uint32
}

type ypfInfo struct {
	Header        ypfHeader
	ArchivedFiles []ypfEntry
}

func getLengthSwappingTable(version uint32) []byte {
	if version >= 500 {
		return []byte{0, 1, 2, 10, 4, 5, 53, 7, 8, 11, 3, 9, 16, 19, 14, 15, 12, 24, 18, 13, 46, 27, 22, 23, 17, 25, 26, 21, 30, 29, 28, 31, 35, 33, 34, 32, 36, 37, 41, 39, 40, 38, 42, 43, 47, 45, 20, 44, 48, 49, 50, 51, 52, 6, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255}
	}
	return []byte{0, 1, 2, 72, 4, 5, 53, 7, 8, 11, 10, 9, 16, 19, 14, 15, 12, 25, 18, 13, 20, 27, 22, 23, 24, 17, 26, 21, 30, 29, 28, 31, 35, 33, 34, 32, 36, 37, 41, 39, 40, 38, 42, 43, 47, 45, 50, 44, 48, 49, 46, 51, 52, 6, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 3, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255}
}

func getFileNameEncryptionKey(version uint32) byte {
	if version == 290 {
		return 64
	}
	if version > 500 {
		return 54
	}
	return 0
}

func parseYpf(oriStm []byte, codePage int) (archive ypfInfo, err error) {
	stm := bytes.NewReader(oriStm)
	binary.Read(stm, binary.LittleEndian, &archive.Header)
	logln("header:", archive.Header)
	header := &archive.Header
	if bytes.Compare(header.Meta.Magic[:], []byte("YPF\x00")) != 0 {
		err = fmt.Errorf("not a ypf file")
		return
	}
	archive.ArchivedFiles = make([]ypfEntry, archive.Header.Num)
	lengthSwappingTable := getLengthSwappingTable(archive.Header.Meta.Version)
	fileNameEncryptionKey := getFileNameEncryptionKey(archive.Header.Meta.Version)
	for i := 0; i < int(archive.Header.Num); i++ {
		entry := &archive.ArchivedFiles[i]
		binary.Read(stm, binary.LittleEndian, &entry.NameChecksum)
		var b byte
		binary.Read(stm, binary.LittleEndian, &b)
		b = ^b
		b2 := lengthSwappingTable[int(b)]
		array := make([]byte, int(b2))
		stm.Read(array)
		for j := 0; j < int(b2); j++ {
			array[j] = (^array[j]) ^ fileNameEncryptionKey
		}
		entry.FileName = codec.Decode(array, codePage)
		binary.Read(stm, binary.LittleEndian, &entry.Type)
		binary.Read(stm, binary.LittleEndian, &entry.IsCompressed)
		binary.Read(stm, binary.LittleEndian, &entry.RawFileSize)
		binary.Read(stm, binary.LittleEndian, &entry.CompressedFileSize)
		if archive.Header.Meta.Version < 479 {
			var o uint32
			binary.Read(stm, binary.LittleEndian, &o)
			entry.Offset = uint64(o)
		} else {
			binary.Read(stm, binary.LittleEndian, &entry.Offset)
		}
		binary.Read(stm, binary.LittleEndian, &entry.DataChecksum)
	}
	sort.Slice(archive.ArchivedFiles[:], func(i, j int) bool {
		return archive.ArchivedFiles[i].Offset < archive.ArchivedFiles[j].Offset
	})
	return
}

func extractFileFromYpf(oriStm []byte, entry ypfEntry) (fileBytes []byte, err error) {
	stm := bytes.NewReader(oriStm)
	var header ypfHeader
	binary.Read(stm, binary.LittleEndian, &header)
	logln("header:", header)
	if bytes.Compare(header.Meta.Magic[:], []byte("YPF\x00")) != 0 {
		err = fmt.Errorf("not a ypf file")
		return
	}
	stm.Seek(int64(entry.Offset), io.SeekStart)
	a := make([]byte, entry.CompressedFileSize)
	stm.Read(a)
	if entry.IsCompressed != 1 {
		fileBytes = make([]byte, len(a))
		re := bytes.NewReader(a)
		re.Read(fileBytes)
		return
	}
	fileBytes = make([]byte, entry.RawFileSize)
	buf := bytes.NewReader(a)
	r, e := zlib.NewReader(buf)
	if e != nil {
		err = e
		return
	}
	r.Read(fileBytes)
	return
}
