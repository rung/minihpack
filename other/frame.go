package minihttp2

import (
	"io"
	"encoding/binary"
	"./hpack"
	"errors"
	"bytes"
)


// Connection Preface
// MAGIC
var CONNECTION_PREFACE string = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func WriteMAGIC(w io.Writer) {
	w.Write([]byte(CONNECTION_PREFACE))
	return
}

// Frame Type is defined
type FrameType uint8

const (
	FrameData         FrameType = 0x0
	FrameHeaders      FrameType = 0x1
	FramePriority     FrameType = 0x2
	FrameRSTStream    FrameType = 0x3
	FrameSettings     FrameType = 0x4
	FramePushPromise  FrameType = 0x5
	FramePing         FrameType = 0x6
	FrameGoAway       FrameType = 0x7
	FrameWindowUpdate FrameType = 0x8
	FrameContinuation FrameType = 0x9
)

var frameName = map[FrameType]string{
	FrameData:         "DATA",
	FrameHeaders:      "HEADERS",
	FramePriority:     "PRIORITY",
	FrameRSTStream:    "RST_STREAM",
	FrameSettings:     "SETTINGS",
	FramePushPromise:  "PUSH_PROMISE",
	FramePing:         "PING",
	FrameGoAway:       "GOAWAY",
	FrameWindowUpdate: "WINDOW_UPDATE",
	FrameContinuation: "CONTINUATION",
}

// Error Code (used by RST_STREAM and GOAWAY)
type ErrorCode uint32
const (
	NO_ERROR          ErrorCode  = 0x0
	PROTOCOL_ERROR      = 0x1
	INTERNAL_ERROR      = 0x2
	FLOW_CONTROL_ERROR  = 0x3
	SETTINGS_TIMEOUT    = 0x4
	STREAM_CLOSED       = 0x5
	FRAME_SIZE_ERROR    = 0x6
	REFUSED_STREAM      = 0x7
	CANCEL              = 0x8
	COMPRESSION_ERROR   = 0x9
	CONNECT_ERROR       = 0xa
	ENHANCE_YOUR_CALM   = 0xb
	INADEQUATE_SECURITY = 0xc
	HTTP_1_1_REQUIRED   = 0xd
)




// 4.1.  Frame Format
//
//   All frames begin with a fixed 9-octet header followed by a variable-
//   length payload.
//
//    +-----------------------------------------------+
//    |                 Length (24)                   |
//    +---------------+---------------+---------------+
//    |   Type (8)    |   Flags (8)   |
//    +-+-------------+---------------+-------------------------------+
//    |R|                 Stream Identifier (31)                      |
//    +=+=============================================================+
//    |                   Frame Payload (0...)                      ...
//    +---------------------------------------------------------------+
//
//                          Figure 1: Frame Layout
type Framer struct {
	Length   uint32    // 24bit
	FType    FrameType // 8bit
	Flags    uint8     // 8bit
	StreamID uint32    // R(1bit) + Stream Identifier(31bit)
}

func (f *Framer) writeFrame(w io.Writer) error {
	// write length + Type
	var b uint32 = (f.Length << 8) + uint32(f.FType)
	binary.Write(w, binary.BigEndian, b)

	// write flags
	binary.Write(w, binary.BigEndian, f.Flags)

	// write R + Stream ID
	binary.Write(w, binary.BigEndian, f.StreamID)

	return nil
}

type NotEnoughByte struct{
}

func (n NotEnoughByte) Error() string{
	return "not enough byte"
}

// return framer, framepaylad, remainbyte, error
func ReadFrame(b []byte) (*Framer, []byte, []byte, error) {
	if len(b) < 9 {
		return nil, nil, nil, NotEnoughByte{}
	}
	// read length + Type
	frame := &Framer{
		Length:   uint32(b[0]<<16 | b[1]<<8 | b[2]),
		FType:    FrameType(b[3]),
		Flags:    uint8(b[4]),
		StreamID: uint32(b[5]<<24|b[6]<<16|b[7]<<8|b[8]) & (1<<31 - 1), // 1 << 31 -1 equal 0111111... (this purpose is to change first bit to zero)
	}
	if uint32(len(b)) < frame.Length + 9 {
		return nil, nil, nil, NotEnoughByte{}
	}

	payload := b[9:9+frame.Length]
	remain := b[9+frame.Length:]
	return frame, payload, remain, nil
}

// DATA
//    +---------------+
//    |Pad Length? (8)|
//    +---------------+-----------------------------------------------+
//    |                            Data (*)                         ...
//    +---------------------------------------------------------------+
//    |                           Padding (*)                       ...
//    +---------------------------------------------------------------+
//
//                       Figure 6: DATA Frame Payload
type Data struct {
	Eos bool
	Content []byte
}

const (
	DATA_END_STREAM = 0x1
	DATA_PADDED = 0x8
)

// Memo: 必ずEND STREAMになるようになってる。
func WriteData(con *Connection, frame *Framer, data []byte) error {
	wBuffer := bytes.Buffer{}

	// overwrite connection's sendHeaderCache
	leng := len(data)
	frame.Length = uint32(leng)
	frame.FType = FrameData
	// Memo: No Padding
	frame.Flags = DATA_END_STREAM
	err := frame.writeFrame(&wBuffer)
	if err != nil {
		return err
	}

	wBuffer.Write(data)
	con.W.Write(wBuffer.Bytes())

	return nil
}

func ParseData(f *Framer, b []byte) (*Data, error){
	if f.FType & FrameData != 0 {
		return nil, errors.New("This is not DATA frame.")
	}

	// contains Pad length
	if (f.Flags & DATA_PADDED) != 0 {
		pad := int(b[0])
		// cut padding
		b = b[1:len(b)-pad]
	}

	d := &Data{
		Eos: (f.Flags & DATA_END_STREAM) == DATA_END_STREAM,
		Content: b,
	}
	return d, nil
}

//----

// HEADER
//
//    +---------------+
//    |Pad Length? (8)|
//    +-+-------------+-----------------------------------------------+
//    |E|                 Stream Dependency? (31)                     |
//    +-+-------------+-----------------------------------------------+
//    |  Weight? (8)  |
//    +-+-------------+-----------------------------------------------+
//    |                   Header Block Fragment (*)                 ...
//    +---------------------------------------------------------------+
//    |                           Padding (*)                       ...
//    +---------------------------------------------------------------+
type Header struct {
	Dependency uint32 // E + Stream Dependency
	Weight     uint8
	Header []hpack.KeyValue
}

const (
	HEADER_END_STREAM = 0x1
	HEADER_END_HEADERS = 0x4
	HEADER_PADDED = 0x8
	HEADER_PRIORITY = 0x20
)

// HEADERS
// +---------------+
// |Pad Length? (8)|
// +-+-------------+-----------------------------------------------+
// |E|                 Stream Dependency? (31)                     |
// +-+-------------+-----------------------------------------------+
// |  Weight? (8)  |
// +-+-------------+-----------------------------------------------+
// |                   Header Block Fragment (*)                 ...
// +---------------------------------------------------------------+
// |                           Padding (*)                       ...
// +---------------------------------------------------------------+
func WriteHeader(con *Connection, frame *Framer, header []hpack.KeyValue) error {
	wBuffer := bytes.Buffer{}
	encodedHeader, sh, err := hpack.EncodeHeader(header, con.sendHeaderCache)
	if err != nil {
		return err
	}
	// overwrite connection's sendHeaderCache
	con.sendHeaderCache = sh
	leng := len(encodedHeader)
	frame.Length = uint32(leng)
	frame.FType = FrameHeaders
	// Memo: No Padding, No dependency only
	frame.Flags = HEADER_END_STREAM|HEADER_END_HEADERS
	err = frame.writeFrame(&wBuffer)
	if err != nil {
		return err
	}

	wBuffer.Write(encodedHeader)
	con.W.Write(wBuffer.Bytes())

	return nil
}

func ParseHeader(con *Connection, frame *Framer, b []byte) (*Header, error) {
	var header *Header
	if frame.FType & FrameHeaders != 0 {
		return nil, errors.New("This is not HEADERS frame.")
	}

	// contains Pad length
	if (frame.Flags & HEADER_PADDED) != 0 {
		pad := int(b[0])
		// cut padding
		b = b[1:len(b)-pad]
	}

	// contains dependency
	// Memo: not correspond to dependency&weight
	if (frame.Flags & HEADER_PRIORITY) != 0 {
		header.Dependency = uint32(b[0] << 24 + b[1] << 16 + b[2] << 8 + b[3])
		header.Weight = uint8(b[4])
		b = b[5:]
	}

	// decode header
	h, hc, err := hpack.DecodeHeader(b, con.receiveHeaderCache)
	if err != nil {
		return nil, err
	}
	con.receiveHeaderCache = hc
	header.Header = h
	return header, nil
}


// PRIORITY
//
//    +-+-------------------------------------------------------------+
//    |E|                  Stream Dependency (31)                     |
//    +-+-------------+-----------------------------------------------+
//    |   Weight (8)  |
//    +-+-------------+
type Priority struct {
	Dependency uint32
	Weight uint8
}
func ParsePriority(f *Framer, b []byte) (*Priority, error){
	p := &Priority{
		Dependency: uint32(b[0]<<24 + b[1]<<16 + b[2]<<8 + b[3]),
		Weight: b[4],
	}
	return p, nil
}

// RST_STREAM
//    +---------------------------------------------------------------+
//    |                        Error Code (32)                        |
//    +---------------------------------------------------------------+
type RstStream struct {
	Error ErrorCode
}

func ParseRstStream(f *Framer, b []byte) (*RstStream, error){
	if f.StreamID == 0 {
		return nil, errors.New("RstStream's id must not be 0")
	}

	rs := &RstStream{
		Error 		: ErrorCode(b[0]<<24 + b[1]<<16 + b[2]<<8 + b[3]),
	}

	return rs, nil

}


// SETTINGS FORMAT
//    +-------------------------------+
//    |       Identifier (16)         |
//    +-------------------------------+-------------------------------+
//    |                        Value (32)                             |
//    +---------------------------------------------------------------+
const (
	SETTINGS_ACK = 0x1
)

type Settings struct {
	Id    SettingsId
	Value uint32
	Ack bool
}
//
type SettingsId uint16
//
const (
	HEADER_TABLE_SIZE      SettingsId = 0x1
	ENABLE_PUSH            SettingsId = 0x2
	MAX_CONCURRENT_STREAMS SettingsId = 0x3
	INITIAL_WINDOW_SIZE    SettingsId = 0x4
	MAX_FRAME_SIZE         SettingsId = 0x5
	MAX_HEADER_LIST_SIZE   SettingsId = 0x6
)

func (con *Connection) WriteSettings(frame *Framer, d Settings) error {
	wBuffer := bytes.Buffer{}
	frame.FType = FrameSettings
	var leng int
	if d.Id == 0 {
		leng = 0
	} else {
		leng = 6
	}
	frame.Length = uint32(leng)

	if d.Ack == true {
		frame.Flags = SETTINGS_ACK
	}

	err := frame.writeFrame(&wBuffer)
	if err != nil {
		return err
	}

	if leng != 0 {
		binary.Write(&wBuffer, binary.BigEndian, d.Id)
		binary.Write(&wBuffer, binary.BigEndian, d.Value)
	}
	con.W.Write(wBuffer.Bytes())

	return nil
}


// parse and error handling
func ParseSettings(f *Framer, b []byte) (*Settings, error) {
	s := &Settings{
		Id:    SettingsId((b[0] << 8) + b[1]),
		Value: uint32(b[2]<<24 + b[3]<<16 + b[4]<<8 + b[5]),
		Ack: (f.Flags == SETTINGS_ACK),
	}

	if s.Ack == true && s.Value != 0 {
		return nil, errors.New("value is wrong(ack==true and value not null)")
	}

	return s, nil
}


// PUSH PROMISE
//    +---------------+
//    |Pad Length? (8)|
//    +-+-------------+-----------------------------------------------+
//    |R|                  Promised Stream ID (31)                    |
//    +-+-----------------------------+-------------------------------+
//    |                   Header Block Fragment (*)                 ...
//    +---------------------------------------------------------------+
//    |                           Padding (*)                       ...
//    +---------------------------------------------------------------+



// PING
//    +---------------------------------------------------------------+
//    |                                                               |
//    |                      Opaque Data (64)                         |
//    |                                                               |
//    +---------------------------------------------------------------+
// parse and error handling
func ParsePing(f *Framer, b []byte) (*WindowUpdate, error) {
	wu := &WindowUpdate{
		WindowSizeIncrement:    uint32((b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3]),
	}

	return wu, nil
}


// GO AWAY
//    +-+-------------------------------------------------------------+
//    |R|                  Last-Stream-ID (31)                        |
//    +-+-------------------------------------------------------------+
//    |                      Error Code (32)                          |
//    +---------------------------------------------------------------+
//    |                  Additional Debug Data (*)                    |
//    +---------------------------------------------------------------+
type GoAway struct {
	LastStreamId uint32
	Error  ErrorCode
	AdditionalDebugData []byte
}

// parse and error handling
func ParseGoAway(f *Framer, b []byte) (*GoAway, error) {
	if f.StreamID != 0 {
		return nil, errors.New("GoAway frame's stream ID must be 0")
	}

	ga := &GoAway{
		LastStreamId:    uint32((b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3]),
		Error: ErrorCode(b[4]<<24 + b[5]<<16 + b[6]<<8 + b[7]),
	}

	if len(b) > 8 {
		ga.AdditionalDebugData = b[8:]
	}

	return ga, nil
}



// WINDOW UPDATE
//    +-+-------------------------------------------------------------+
//    |R|              Window Size Increment (31)                     |
//    +-+-------------------------------------------------------------+
type WindowUpdate struct {
	WindowSizeIncrement uint32 // R+Window Size Increment (31)
}

// parse and error handling
func ParseWindowUpdate(f *Framer, b []byte) (*WindowUpdate, error) {
	wu := &WindowUpdate{
		WindowSizeIncrement:    uint32((b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3]),
	}

	return wu, nil
}


// CONTINUAION
//    +---------------------------------------------------------------+
//    |                   Header Block Fragment (*)                 ...
//    +---------------------------------------------------------------+
type Continuation struct {
	Header []hpack.KeyValue
}

// parse and error handling
func ParseContinuation(con *Connection, b []byte) (*Continuation, error) {
	kv, hc, err := hpack.DecodeHeader(b, con.receiveHeaderCache)
	if err != nil {
		return nil, err
	}

	con.receiveHeaderCache = hc

	return &Continuation{Header: kv}, nil
}







