package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/regomne/eutil/codec"
	"os"
)

type ysvrHeader struct {
	Meta  GenericHeader
	Count uint16
}

type ysvrInfo struct {
	Header ysvrHeader
	Data   []ysvrVariable
}

type ysvrVariableHeader struct {
	Scope    uint8 // 1 = global, 2 = static
	ScriptId uint16
	VarIndex uint16
	Type     uint8 // 1 = long, 2 = double, 3 = string
	DimCount uint8
}

type ysvrVariable struct {
	Header  ysvrVariableHeader
	DimSize []uint32
	Data    any
}

func parseYsvrFile(oriStm []byte, outJsonName string, codePage int) bool {
	logln("parsing ybn...")
	script, err := parseYsvr(oriStm, codePage)
	if err != nil {
		fmt.Println("parse error:", err)
		return false
	}
	if outJsonName != "" {
		logln("writing json...")
		out, err := json.MarshalIndent(script, "", "\t")
		if err != nil {
			fmt.Println("error when marshalling json:", err)
			return false
		}
		os.WriteFile(outJsonName, out, os.ModePerm)
	}
	logln("complete.")
	return true
}

func parseYsvr(oriStm []byte, codePage int) (script ysvrInfo, err error) {
	stm := bytes.NewReader(oriStm)
	binary.Read(stm, binary.LittleEndian, &script.Header)
	logln("header:", script.Header)
	header := &script.Header
	if bytes.Compare(header.Meta.Magic[:], []byte("YSVR")) != 0 {
		err = fmt.Errorf("not a ybn file")
		return
	}
	script.Data = make([]ysvrVariable, script.Header.Count)
	for i := 0; i < int(script.Header.Count); i++ {
		datatype := &script.Data[i]
		binary.Read(stm, binary.LittleEndian, &datatype.Header)
		datatype.DimSize = make([]uint32, datatype.Header.DimCount)
		binary.Read(stm, binary.LittleEndian, &datatype.DimSize)
		switch datatype.Header.Type {
		case 0:
			break
		case 1:
			var i int64
			binary.Read(stm, binary.LittleEndian, &i)
			datatype.Data = i
			break
		case 2:
			var i float64
			binary.Read(stm, binary.LittleEndian, &i)
			datatype.Data = i
			break
		case 3:
			var i uint16
			binary.Read(stm, binary.LittleEndian, &i)
			b := make([]byte, i)
			stm.Read(b)
			datatype.Data = codec.Decode(b[:], codePage)
			break
		}
	}
	return
}
