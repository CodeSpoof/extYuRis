package main

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"github.com/aviddiviner/go-murmur"
	"github.com/regomne/eutil/codec"
	"hash/adler32"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
)

type ypfHeader struct {
	Meta                    GenericHeader
	FileCount               uint32
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
	archive.ArchivedFiles = make([]ypfEntry, archive.Header.FileCount)
	lengthSwappingTable := getLengthSwappingTable(archive.Header.Meta.Version)
	fileNameEncryptionKey := getFileNameEncryptionKey(archive.Header.Meta.Version)
	for i := 0; i < int(archive.Header.FileCount); i++ {
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
		if entry.NameChecksum != checksumByVersion(array, header.Meta.Version, true) {
			err = fmt.Errorf("name check failed for %s", entry.FileName)
			return
		}
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

func checksumByVersion(data []byte, version uint32, isName bool) uint32 {
	if version < 479 {
		if isName {
			return crc32.Checksum(data, &crc32.Table{
				0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
				0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
				0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
				0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
				0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
				0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
				0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
				0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
				0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
				0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
				0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
				0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
				0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
				0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
				0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
				0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
				0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
				0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
				0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
				0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
				0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
				0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
				0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
				0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
				0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
				0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
				0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
				0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
				0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
				0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
				0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
				0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
			})
		} else {
			return adler32.Checksum(data)
		}
	} else {
		return murmur.MurmurHash2(data, 0)
	}
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
	if entry.DataChecksum != checksumByVersion(a, header.Meta.Version, false) {
		err = fmt.Errorf("data check failed for %s", entry.FileName)
	}
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

func IndexOfByte(arr []byte, candidate byte) byte {
	for index, c := range arr {
		if c == candidate {
			return byte(index)
		}
	}
	return 0
}

func packYpf(outputYpf, inputDir string, version, codePage int) bool {
	input, _ := filepath.Abs(inputDir)
	offInput := len(input) + 1
	var files []string
	err := filepath.WalkDir(input, func(path string, info os.DirEntry, err error) error {
		if err == nil && !info.IsDir() {
			files = append(files, path[offInput:])
		}
		return nil
	})
	if err != nil {
		fmt.Println("Error while listing files")
		return false
	}

	var header ypfHeader
	header.Meta.Version = uint32(version)
	header.FileCount = uint32(len(files))
	header.ArchivedFilesHeaderSize = 32
	entries := make([]ypfEntry, len(files))

	typeMap := map[string]uint8{
		"txt": 0,
		"bmp": 1,
		"png": 2,
		"jpg": 3,
		"gif": 4,
		"wav": 5,
		"ogg": 6,
		"psd": 7,
		"ycg": 8, //masked as .png
		"psb": 9,
	}

	i := 0
	for _, file := range files {
		entry := &entries[i]
		entry.FileName = file
		fileExt := filepath.Ext(file)
		if fileExt == "ycg" {
			entry.FileName = entry.FileName[:len(entry.FileName)-4]
		}
		if len(entry.FileName) == 0 {
			fmt.Println("Filename can't be empty")
			return false
		}
		for j := 0; j < i; j++ {
			if entries[j].FileName == entry.FileName {
				fmt.Println("Filenames can't be duplicates")
				return false
			}
		}
		encodedName := []byte(entry.FileName)
		entry.NameChecksum = checksumByVersion(encodedName, uint32(version), true)
		r, ok := typeMap[fileExt]
		if !ok {
			r = 0
		}
		entry.Type = r
		header.ArchivedFilesHeaderSize += uint32(23 + len(encodedName))
		if header.Meta.Version >= 479 {
			header.ArchivedFilesHeaderSize += 4
		}
		i++
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].NameChecksum < entries[j].NameChecksum
	})
	var outBuff bytes.Buffer

	for _, entry := range entries {
		fmt.Printf("Adding %s\n", entry.FileName)
		filePath := filepath.Join(inputDir, entry.FileName)
		if entry.Type == typeMap["ycg"] {
			filePath += ".ycg"
		}
		fileBytes, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Println("Error while reading file")
			return false
		}
		if len(fileBytes) > 0xFFFFFFFF {
			fmt.Println("File too large")
			return false
		}
		if len(fileBytes) == 0 {
			fmt.Println("File empty")
			return false
		}
		entry.Offset = uint64(uint32(len(outBuff.Bytes())) + header.ArchivedFilesHeaderSize)
		entry.RawFileSize = uint32(len(fileBytes))

		var compressed bytes.Buffer
		w := zlib.NewWriter(&compressed)
		w.Write(fileBytes)

		if len(compressed.Bytes()) < len(fileBytes) {
			entry.DataChecksum = checksumByVersion(compressed.Bytes(), uint32(version), false)
			for _, e := range entries {
				if e.DataChecksum == entry.DataChecksum && e.RawFileSize == entry.RawFileSize {
					entry.Offset = e.Offset
					break
				} else {
					outBuff.Write(compressed.Bytes())
				}
			}
			entry.CompressedFileSize = uint32(len(compressed.Bytes()))
			entry.IsCompressed = 1
		} else {
			entry.DataChecksum = checksumByVersion(fileBytes, uint32(version), false)
			for _, e := range entries {
				if e.DataChecksum == entry.DataChecksum && e.RawFileSize == entry.RawFileSize {
					entry.Offset = e.Offset
					break
				} else {
					outBuff.Write(fileBytes)
				}
			}
			entry.CompressedFileSize = entry.RawFileSize
			entry.IsCompressed = 0
		}
		if version < 479 && len(outBuff.Bytes()) > 0xFFFFFFFF {
			fmt.Println("Output file too long")
			return false
		}

	}
	var fullBuff bytes.Buffer
	binary.Write(&fullBuff, binary.LittleEndian, header)

	for _, entry := range entries {
		binary.Write(&fullBuff, binary.LittleEndian, entry.NameChecksum)
		encodedName := codec.Encode(entry.FileName, codePage, codec.Replace)
		if len(encodedName) > 0xFF {
			fmt.Println("Filename can only be one byte")
			return false
		}
		lengthEncoded := IndexOfByte(getLengthSwappingTable(uint32(version)), byte(len(encodedName)))
		binary.Write(&fullBuff, binary.LittleEndian, lengthEncoded)
		for i := range encodedName {
			encodedName[i] = ^(encodedName[i] ^ getFileNameEncryptionKey(uint32(version)))
		}
		fullBuff.Write(encodedName)
		binary.Write(&fullBuff, binary.LittleEndian, entry.Type)
		binary.Write(&fullBuff, binary.LittleEndian, entry.IsCompressed)
		binary.Write(&fullBuff, binary.LittleEndian, entry.RawFileSize)
		binary.Write(&fullBuff, binary.LittleEndian, entry.CompressedFileSize)
		if version < 479 {
			binary.Write(&fullBuff, binary.LittleEndian, uint32(entry.Offset))
		} else {
			binary.Write(&fullBuff, binary.LittleEndian, entry.Offset)
		}
		binary.Write(&fullBuff, binary.LittleEndian, entry.DataChecksum)
	}
	if uint32(len(fullBuff.Bytes())) != header.ArchivedFilesHeaderSize {
		fmt.Println("Oversized Header")
		return false
	}
	outBuff.WriteTo(&fullBuff)
	err = os.WriteFile(outputYpf, fullBuff.Bytes(), os.ModePerm)
	if err != nil {
		fmt.Println("Error while writing archive")
		return false
	}
	return true
}

func extractYpf(oriStm []byte, outputDir string, codePage int) bool {
	ypf, err := parseYpf(oriStm, codePage)
	if err != nil {
		return false
	}
	for _, file := range ypf.ArchivedFiles {
		fileBytes, err := extractFileFromYpf(oriStm, file)
		if err != nil {
			return false
		}
		os.WriteFile(filepath.Join(outputDir, file.FileName), fileBytes, os.ModePerm)
	}
	return true
}
