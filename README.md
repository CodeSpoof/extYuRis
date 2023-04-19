# extYuRis
An extraction Tool for Yu-Ris Script Engine .ybn files.

Made with code from regomne's extYbn in [chinesize](https://github.com/regomne/chinesize).

## Features
- Supports all ybn files (that I know of)
- Extraction of Strings from Script and Error-Messages
- Extraction of Code (partially readable, not a complete decompiler)
- Extraction of raw data to json
- Export of decrypted binary files
- Guessing of `msg` and `call` Op-Code
- Guessing of encryption key
- Repacking of strings and project configuration

## Usage
See help text when executing the program

## Build from Sources
### Linux
- Install go
- Navigate into cloned repository
- `go get .`
- `go build .`

## Plans
- Repacking of all formats from json and maybe from instruct
- Guessing of more Op-Codes (especially END)
- Extraction/Repacking of YPF archives
- (UI + edit directly inside YPF?)
