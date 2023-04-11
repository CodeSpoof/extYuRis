package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/regomne/eutil/codec"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type yscfHeader struct {
	Meta           YbnHeader
	Padding1       uint32
	Compile        uint32
	ScreenWidth    uint32
	ScreenHeight   uint32
	Enable         uint32
	ImageTypeSlots [8]byte
	SoundTypeSlots [4]byte
	Thread         uint32
	DebugMode      uint32
	Sound          uint32
	WindowResize   uint32
	WindowFrame    uint32
	FilePriority   FilePriority // 0 = Archive, 1 = Folder
	Padding2       uint32
	CaptionLength  uint16
}

type FilePriority struct {
	Dev     uint32
	Debug   uint32
	Release uint32
}

type yscfInfo struct {
	Header  yscfHeader
	Caption string
}

func parseYscfFile(oriStm []byte, outJsonName, outInstructName string, codePage int) bool {
	logln("parsing ybn...")
	script, err := parseYscf(oriStm, codePage)
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
	if outInstructName != "" {
		logln("writing instructions...")
		out := fmt.Sprintf("Version=%v\n", script.Header.Meta.Version)
		out += fmt.Sprintf("Compile=%v\n", script.Header.Compile)
		out += fmt.Sprintf("ScreenWidth=%v\n", script.Header.ScreenWidth)
		out += fmt.Sprintf("ScreenHeight=%v\n", script.Header.ScreenHeight)
		out += fmt.Sprintf("Enable=%v\n", script.Header.Enable)
		out += fmt.Sprintf("ImageTypeSlots=%v\n", script.Header.ImageTypeSlots)
		out += fmt.Sprintf("SoundTypeSlots=%v\n", script.Header.SoundTypeSlots)
		out += fmt.Sprintf("Thread=%v\n", script.Header.Thread)
		out += fmt.Sprintf("DebugMode=%v\n", script.Header.DebugMode)
		out += fmt.Sprintf("Sound=%v\n", script.Header.Sound)
		out += fmt.Sprintf("WindowResize=%v\n", script.Header.WindowResize)
		out += fmt.Sprintf("WindowFrame=%v\n", script.Header.WindowFrame)
		out += fmt.Sprintf("FilePriorityDev=%v\n", script.Header.FilePriority.Dev)
		out += fmt.Sprintf("FilePriorityDebug=%v\n", script.Header.FilePriority.Debug)
		out += fmt.Sprintf("FilePriorityRelease=%v\n", script.Header.FilePriority.Release)
		out += fmt.Sprintf("Caption=%v\n", script.Caption)
		strings.TrimRight(out, "\n")
		os.WriteFile(outInstructName, []byte(out), os.ModePerm)
	}
	logln("complete.")
	return true
}

func parseYscf(oriStm []byte, codePage int) (script yscfInfo, err error) {
	stm := bytes.NewReader(oriStm)
	binary.Read(stm, binary.LittleEndian, &script.Header)
	logln("header:", script.Header)
	header := &script.Header
	if bytes.Compare(header.Meta.Magic[:], []byte("YSCF")) != 0 {
		err = fmt.Errorf("not a ybn file")
		return
	}
	captionBytes := make([]byte, script.Header.CaptionLength)
	stm.Read(captionBytes)
	script.Caption = codec.Decode(captionBytes, codePage)
	return
}

func packYscfFile(oriStm []byte, outInstructName, outYbnName string, codePage int) bool {
	logln("parsing ybn...")
	script, err := parseYscf(oriStm, codePage)
	if err != nil {
		fmt.Println("parse error:", err)
		return false
	}
	if outInstructName != "" {
		logln("loading files...")
		txt, err := readFileToString(outInstructName, codePage)
		if err != nil {
			fmt.Println(err)
			return false
		}
		logln("encoding text and writing...")
		reg, err := regexp.Compile("^(?:Version=([0-9]+)\\n?)?(?:Compile=([0-9]+)\\n?)?(?:ScreenWidth=([0-9]+)\\n?)?(?:ScreenHeight=([0-9]+)\\n?)?(?:Enable=([0-9]+)\\n?)?(?:ImageTypeSlots=\\[((?:[0-9] ?)*)]\\n?)?(?:SoundTypeSlots=\\[((?:[0-9] ?)*)]\\n?)?(?:Thread=([0-9]+)\\n?)?(?:DebugMode=([0-9]+)\\n?)?(?:Sound=([0-9]+)\\n?)?(?:WindowResize=([0-9]+)\\n?)?(?:WindowFrame=([0-9]+)\\n?)?(?:FilePriorityDev=([0-9]+)\\n?)?(?:FilePriorityDebug=([0-9]+)\\n?)?(?:FilePriorityRelease=([0-9]+)\\n?)?(?:Caption=(.+)\\n?)?")
		if err != nil {
			fmt.Println(err)
			return false
		}
		matches := reg.FindStringSubmatch(txt)
		for i := 1; i < len(matches); i++ {
			if matches[i] == "" {
				continue
			}
			var e error
			var in int
			switch i {
			case 1:
				in, e = strconv.Atoi(matches[i])
				if e != nil {
					return false
				}
				script.Header.Meta.Version = uint32(in)
			case 2:
				in, e = strconv.Atoi(matches[i])
				if e != nil {
					return false
				}
				script.Header.Compile = uint32(in)
			case 3:
				in, e = strconv.Atoi(matches[i])
				if e != nil {
					return false
				}
				script.Header.ScreenWidth = uint32(in)
			case 4:
				in, e = strconv.Atoi(matches[i])
				if e != nil {
					return false
				}
				script.Header.ScreenHeight = uint32(in)
			case 5:
				in, e = strconv.Atoi(matches[i])
				if e != nil {
					return false
				}
				script.Header.Enable = uint32(in)
			case 6:
				t := strings.Split(matches[i], " ")
				var a [8]byte
				for j, s := range t {
					in, e = strconv.Atoi(s)
					if e != nil {
						return false
					}
					a[j] = byte(in)
				}
				script.Header.ImageTypeSlots = a
			case 7:
				t := strings.Split(matches[i], " ")
				var a [4]byte
				for j, s := range t {
					in, e = strconv.Atoi(s)
					if e != nil {
						return false
					}
					a[j] = byte(in)
				}
				script.Header.SoundTypeSlots = a
			case 8:
				in, e = strconv.Atoi(matches[i])
				if e != nil {
					return false
				}
				script.Header.Thread = uint32(in)
			case 9:
				in, e = strconv.Atoi(matches[i])
				if e != nil {
					return false
				}
				script.Header.DebugMode = uint32(in)
			case 10:
				in, e = strconv.Atoi(matches[i])
				if e != nil {
					return false
				}
				script.Header.Sound = uint32(in)
			case 11:
				in, e = strconv.Atoi(matches[i])
				if e != nil {
					return false
				}
				script.Header.WindowResize = uint32(in)
			case 12:
				in, e = strconv.Atoi(matches[i])
				if e != nil {
					return false
				}
				script.Header.WindowFrame = uint32(in)
			case 13:
				in, e = strconv.Atoi(matches[i])
				if e != nil {
					return false
				}
				script.Header.FilePriority.Dev = uint32(in)
			case 14:
				in, e = strconv.Atoi(matches[i])
				if e != nil {
					return false
				}
				script.Header.FilePriority.Debug = uint32(in)
			case 15:
				in, e = strconv.Atoi(matches[i])
				if e != nil {
					return false
				}
				script.Header.FilePriority.Release = uint32(in)
			case 16:
				script.Header.CaptionLength = uint16(len(matches[i]))
				script.Caption = matches[i]
			}
		}
		var buffer bytes.Buffer
		binary.Write(&buffer, binary.LittleEndian, script.Header)
		buffer.Write(codec.Encode(script.Caption, codePage, codec.Replace))
		os.WriteFile(outYbnName, buffer.Bytes(), os.ModePerm)
	}
	logln("complete.")
	return true
}
