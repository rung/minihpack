package minihttp2

import (
	"bytes"
	"testing"
)

func TestPreface(t *testing.T) {
	test := &bytes.Buffer{}
	WriteMAGIC(test)
	if !bytes.Equal(test.Bytes(), []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
		t.Fatal("preface have a problem")
	}
}



func TestParseGoAway(t *testing.T) {
	// Doesn't contain Additional Debug Data
	f := &Framer{
		8,
		FrameGoAway,
		0,
		0x0,
	}

	// Last Stream Id = 1
	// Error Code = 1 (PROTOCOL_ERROR)
	testOriginal := []byte{0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01}
	v, _:= ParseGoAway(f, testOriginal)
	if v.LastStreamId != 0x01 {
		t.Fatalf("Error: ParseGoAway Error", v.LastStreamId)
	}
	if v.Error != PROTOCOL_ERROR {
		t.Fatalf("Error: ParseGoAway Error", v.Error)
	}
	if len(v.AdditionalDebugData) != 0 {
		t.Fatalf("Error: ParseGoAway Error", v.AdditionalDebugData)
	}

	// Contains Additonal Debug Data
	// StreamId Of GoAway Frame must be 0.
	f = &Framer{
		8,
		FrameGoAway,
		0,
		0x0,
	}

	// Last Stream Id = 0
	// Error Code = 1 (PROTOCOL_ERROR)
	testOriginal = []byte{0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01}
	testOriginal = append(testOriginal, []byte("GoAway")...)
	v, _= ParseGoAway(f, testOriginal)
	if v.Error != PROTOCOL_ERROR {
		t.Fatalf("Error: ParseGoAway Error", v.Error)
	}
	if string(v.AdditionalDebugData) != "GoAway" {
		t.Fatalf("Error: ParseGoAway AdditionalDebugData", v.AdditionalDebugData)
	}

	// Error Case
	// StreamId != 0
	f = &Framer{
		8,
		FrameGoAway,
		0,
		0x1,
	}
	testOriginal = []byte{0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01}
	testOriginal = append(testOriginal, []byte("GoAway")...)
	_, err:= ParseGoAway(f, testOriginal)
	if err == nil {
		t.Fatalf("Error: ParseGoAway doesn't send error", err)
	}

}

func TestParseData(t *testing.T) {
	// Without Padding
	f := &Framer{
		8,
		FrameData,
		0,
		0x0,
	}
	testOriginal := []byte("Data Test")
	v, _ := ParseData(f, testOriginal)
	if string(v.Content) != "Data Test"{
		t.Fatalf("Error: ParseData doen't correct parse %v", v.Content)
	}

	// with Padding
	f.Flags |= DATA_PADDED
	testOriginal = []byte{0x2}
	testOriginal = append(testOriginal,[]byte("Data Test")...)
	testOriginal = append(testOriginal,[]byte{0x0,0x0}...)

	v, _ = ParseData(f, testOriginal)
	if string(v.Content) != "Data Test"{
		t.Fatalf("Error: ParseData doen't correct parse %v", v.Content)
	}

}