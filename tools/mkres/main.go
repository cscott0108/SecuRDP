// mkres generates the Windows resources for securdp.exe (icon, manifest,
// version info) as rsrc_windows_amd64.syso, which `go build` links in
// automatically, plus the UI's icon.png. Run from the repo root:
//
//	go run ./tools/mkres
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	ver "securdp/internal/version"
)

const version = ver.Version

const (
	rtIcon    = 3
	rtGroup   = 14
	rtVersion = 16
	rtManifst = 24
	langEN    = 0x0409
)

var iconSizes = []int{16, 20, 24, 32, 40, 48, 64, 96, 128, 256}

type resource struct {
	typ, id, lang uint16
	data          []byte
}

func main() {
	var res []resource

	// RT_ICON entries (PNG-encoded, supported since Windows Vista) + RT_GROUP_ICON #1.
	var grp bytes.Buffer
	le(&grp, uint16(0), uint16(1), uint16(len(iconSizes)))
	for i, s := range iconSizes {
		data := pngBytes(renderIcon(s))
		id := uint16(i + 1)
		res = append(res, resource{rtIcon, id, langEN, data})
		dim := uint8(s)
		if s >= 256 {
			dim = 0
		}
		le(&grp, dim, dim, uint8(0), uint8(0), uint16(1), uint16(32), uint32(len(data)), id)
	}
	res = append(res, resource{rtGroup, 1, langEN, grp.Bytes()})
	res = append(res, resource{rtVersion, 1, langEN, versionInfo()})
	res = append(res, resource{rtManifst, 1, langEN, []byte(manifest)})

	must(os.WriteFile("rsrc_windows_amd64.syso", coff(res), 0o644))
	must(os.WriteFile("internal/gui/web/icon.png", pngBytes(renderIcon(64)), 0o644))

	// Android adaptive-icon foreground layers (108dp canvas, art in the safe zone).
	for dir, px := range map[string]int{"mdpi": 108, "hdpi": 162, "xhdpi": 216, "xxhdpi": 324, "xxxhdpi": 432} {
		d := "android/app/src/main/res/mipmap-" + dir
		must(os.MkdirAll(d, 0o755))
		must(os.WriteFile(d+"/ic_launcher_foreground.png", pngBytes(renderIconScaled(px, 0.6)), 0o644))
	}
	fmt.Println("wrote rsrc_windows_amd64.syso, internal/gui/web/icon.png and Android launcher icons")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func le(b *bytes.Buffer, vs ...any) {
	for _, v := range vs {
		binary.Write(b, binary.LittleEndian, v)
	}
}

func pad(b *bytes.Buffer, n int) {
	for b.Len()%n != 0 {
		b.WriteByte(0)
	}
}

// coff writes a COFF object containing a .rsrc section. The data-entry RVAs
// are relative to the section and fixed up by the linker via ADDR32NB
// relocations against the section symbol.
func coff(res []resource) []byte {
	sort.Slice(res, func(i, j int) bool {
		if res[i].typ != res[j].typ {
			return res[i].typ < res[j].typ
		}
		return res[i].id < res[j].id
	})
	var types []uint16
	byType := map[uint16][]int{}
	for i, r := range res {
		if len(byType[r.typ]) == 0 {
			types = append(types, r.typ)
		}
		byType[r.typ] = append(byType[r.typ], i)
	}

	// Layout: root dir, type dirs, lang dirs, data entries, then data.
	dirSize := func(n int) int { return 16 + 8*n }
	off := dirSize(len(types))
	typeDirOff := map[uint16]int{}
	for _, t := range types {
		typeDirOff[t] = off
		off += dirSize(len(byType[t]))
	}
	langDirOff := make([]int, len(res))
	for i := range res {
		langDirOff[i] = off
		off += dirSize(1)
	}
	entryOff := make([]int, len(res))
	for i := range res {
		entryOff[i] = off
		off += 16
	}
	dataOff := make([]int, len(res))
	for i, r := range res {
		off = (off + 7) &^ 7
		dataOff[i] = off
		off += len(r.data)
	}

	var sec bytes.Buffer
	dirHeader := func(n int) { le(&sec, uint32(0), uint32(0), uint16(0), uint16(0), uint16(0), uint16(n)) }
	const subdir = 0x80000000
	dirHeader(len(types))
	for _, t := range types {
		le(&sec, uint32(t), uint32(typeDirOff[t])|subdir)
	}
	for _, t := range types {
		dirHeader(len(byType[t]))
		for _, i := range byType[t] {
			le(&sec, uint32(res[i].id), uint32(langDirOff[i])|subdir)
		}
	}
	for i, r := range res {
		dirHeader(1)
		le(&sec, uint32(r.lang), uint32(entryOff[i]))
	}
	var relocs []int
	for i, r := range res {
		relocs = append(relocs, sec.Len())
		le(&sec, uint32(dataOff[i]), uint32(len(r.data)), uint32(0), uint32(0))
	}
	for i, r := range res {
		pad(&sec, 8)
		if sec.Len() != dataOff[i] {
			panic("layout mismatch")
		}
		sec.Write(r.data)
	}
	pad(&sec, 4)

	const hdr, shdr = 20, 40
	rawPtr := hdr + shdr
	relocPtr := rawPtr + sec.Len()
	symPtr := relocPtr + 10*len(relocs)

	var out bytes.Buffer
	// IMAGE_FILE_HEADER (AMD64)
	le(&out, uint16(0x8664), uint16(1), uint32(0), uint32(symPtr), uint32(1), uint16(0), uint16(0))
	// IMAGE_SECTION_HEADER
	out.WriteString(".rsrc\x00\x00\x00")
	le(&out, uint32(0), uint32(0), uint32(sec.Len()), uint32(rawPtr), uint32(relocPtr), uint32(0),
		uint16(len(relocs)), uint16(0), uint32(0x40000040)) // INITIALIZED_DATA | MEM_READ
	out.Write(sec.Bytes())
	for _, r := range relocs {
		le(&out, uint32(r), uint32(0), uint16(3)) // IMAGE_REL_AMD64_ADDR32NB vs symbol 0
	}
	// Symbol table: the section symbol, then an empty string table.
	out.WriteString(".rsrc\x00\x00\x00")
	le(&out, uint32(0), int16(1), uint16(0), uint8(3), uint8(0)) // STATIC
	le(&out, uint32(4))
	return out.Bytes()
}

// --- VS_VERSIONINFO ---

func wstr(s string) []byte {
	var b bytes.Buffer
	for _, u := range utf16.Encode([]rune(s)) {
		le(&b, u)
	}
	le(&b, uint16(0))
	return b.Bytes()
}

// node builds one version-info block: header, key, value, children.
func node(key string, value []byte, valueLen uint16, text bool, children ...[]byte) []byte {
	var b bytes.Buffer
	typ := uint16(0)
	if text {
		typ = 1
	}
	le(&b, uint16(0), valueLen, typ)
	b.Write(wstr(key))
	pad(&b, 4)
	b.Write(value)
	for _, c := range children {
		pad(&b, 4)
		b.Write(c)
	}
	out := b.Bytes()
	binary.LittleEndian.PutUint16(out, uint16(len(out)))
	return out
}

func versionInfo() []byte {
	parts := strings.Split(version, ".")
	v := make([]uint32, 4)
	for i := 0; i < 3 && i < len(parts); i++ {
		n, _ := strconv.Atoi(parts[i])
		v[i] = uint32(n)
	}
	ms, ls := v[0]<<16|v[1], v[2]<<16|v[3]

	var fixed bytes.Buffer
	le(&fixed, uint32(0xFEEF04BD), uint32(0x00010000), ms, ls, ms, ls,
		uint32(0x3F), uint32(0), uint32(0x40004), uint32(1), uint32(0), uint32(0), uint32(0))

	strs := [][2]string{
		{"FileDescription", "SecuRDP - secure Remote Desktop gateway"},
		{"FileVersion", version},
		{"InternalName", "securdp"},
		{"OriginalFilename", "securdp.exe"},
		{"ProductName", "SecuRDP"},
		{"ProductVersion", version},
	}
	var strNodes [][]byte
	for _, kv := range strs {
		val := wstr(kv[1])
		strNodes = append(strNodes, node(kv[0], val, uint16(len(val)/2), true))
	}
	table := node("040904B0", nil, 0, true, strNodes...)
	sfi := node("StringFileInfo", nil, 0, true, table)
	var tr bytes.Buffer
	le(&tr, uint16(langEN), uint16(0x04B0))
	vfi := node("VarFileInfo", nil, 0, true, node("Translation", tr.Bytes(), 4, false))
	return node("VS_VERSION_INFO", fixed.Bytes(), uint16(fixed.Len()), false, sfi, vfi)
}

const manifest = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="SecuRDP" version="` + version + `.0" processorArchitecture="*"/>
  <description>SecuRDP</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/></application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
`
