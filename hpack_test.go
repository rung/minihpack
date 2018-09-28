package hpack

import (
	"fmt"
	"testing"
)

func TestDecodeIntValue(t *testing.T) {
	testOriginal := []byte{0x85, 0x1}
	v, _, _ := decodeIntValue(testOriginal, 5)
	if v != 5 {
		t.Fatalf("Error: decodeIntValue: want=5, ans=%d", v)
	}

	testOriginal = []byte{0x1f, 0x9a, 0xa, 0x1}
	v, _, _ = decodeIntValue(testOriginal, 5)
	if v != 1337 {
		t.Fatalf("Error: decodeIntValue: want=1337, ans=%d", v)
	}
}

func TestEncodeIntValue(t *testing.T) {
	b, _ := encodeIntValue([]byte{3, 128}, 5, 10)
	if b[0] != 3 || b[1] != 138 {
		t.Fatalf("Error encodeIntValue want=3,138, ans=%v", b)
	}
	b, _ = encodeIntValue([]byte{3, 5, 128}, 5, 1337)
	if b[0] != 3 || b[1] != 5 || b[2] != 159 || b[3] != 154 || b[4] != 10 {
		t.Fatalf("Error encodeIntValue 1337 want=3,5,159,154,10, ans=%v", b)
	}
}

func TestEncodeDecodeIntValue(t *testing.T) {
	b, _ := encodeIntValue([]byte{0}, 5, 10)
	v, _, _ := decodeIntValue(b, 5)
	if v != 10 {
		t.Fatalf("Error encode&decodeIntValue: want=10, ans=%d", v)
	}

	b, _ = encodeIntValue([]byte{0}, 5, 1337)
	v, _, _ = decodeIntValue(b, 5)
	if v != 1337 {
		t.Fatalf("Error encode&decodeIntValue: want=1337, ans=%d", v)
	}
}

func TestDecodeStringsValue(t *testing.T) {
	// huffman encoded
	b, _ := encodeIntValue([]byte{128}, 7, 3)
	b = append(b, []byte{0x49, 0x50, 0x9f}...)
	v, _, _ := decodeStrings(b)
	if v != "test" {
		t.Fatalf("Error decodeStringsValue1: want=test, ans=%v", v)
	}

	// not encoded
	b, _ = encodeIntValue([]byte{0}, 7, 4)
	b = append(b, []byte("test")...)
	v, _, _ = decodeStrings(b)
	if v != "test" {
		t.Fatalf("Error decodeStringsValue2: want=test, ans=%v", v)
	}
}

func TestEncodeDecodeStringsValue(t *testing.T) {
	b, _ := encodeStrings([]byte{}, "test", true)
	v, _, _ := decodeStrings(b)
	if v != "test" {
		t.Fatalf("Error encodeDecodeStringsValue: want=test, ans=%v", v)
	}
}

func TestDecodeHeaderTable(t *testing.T) {
	v, _ := decodeHeaderTable(2, nil)
	if v.Key != ":method" || v.Value != "GET" {
		t.Fatalf("Error encodeHeaderTable: want=:method, GET, ans=%v", v)
	}

	v, _ = decodeHeaderTable(61, nil)
	if v.Key != "www-authenticate" || v.Value != "" {
		t.Fatalf("Error encodeHeaderTable: want=:www-authenticate, ans=%v", v)
	}

	dht := []KeyValue{
		KeyValue{"test", "value1"},
		KeyValue{"test2", "value2"},
	}
	v, _ = decodeHeaderTable(63, dht)
	if v.Key != "test2" || v.Value != "value2" {
		t.Fatalf("Error encodeHeaderTable: want=:test, value1, ans=%v", v)
	}
}

func TestEncodeHeaderTable(t *testing.T) {

	nh, ko, i := searchHeaderTable([]KeyValue{}, &KeyValue{"keytest1", "value1"})
	if nh != true || ko != false {
		t.Fatalf("Error encodeHeaderTable: want=true, false, ans=%v %v", nh, ko)
	}
	if i != 0 {
		t.Fatalf("Error encodeHeaderTable: want=0, ans=%v", i)
	}

	nh, ko, i = searchHeaderTable([]KeyValue{}, &KeyValue{":status", "600"})
	if nh != false || ko != true {
		t.Fatalf("Error encodeHeaderTable: want=false, true, ans=%v %v", nh, ko)
	}
	if i != 8 {
		t.Fatalf("Error encodeHeaderTable: want=8, ans=%v", i)
	}

}

func TestDecodeHeader(t *testing.T) {
	// c2.1 example
	encoded := []byte{0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79, 0x0d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72}
	dHeader := []KeyValue{}
	decoded, con, _ := DecodeHeader(encoded, HpackConn{dHeader, 4096})
	if decoded[0].Key != "custom-Key" || decoded[0].Value != "custom-header" {
		t.Fatalf("Error DecodeHeader: want=custom-Key, custom-header, ans=%v", decoded[0])
	}
	if con.DynamicTable[0].Key != "custom-Key" || con.DynamicTable[0].Value != "custom-header" {
		t.Fatalf("Error DecodeHeader: want=custom-Key, custom-header, ans=%v", con.DynamicTable[0])
	}

	// c2.2 example
	encoded = append(encoded, []byte{0x04, 0x0c, 0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70, 0x61, 0x74, 0x68}...)
	decoded, con, _ = DecodeHeader(encoded, HpackConn{[]KeyValue{}, 4096})

	if decoded[0].Key != "custom-Key" || decoded[0].Value != "custom-header" {
		t.Fatalf("Error DecodeHeader: want=custom-Key, custom-header, ans=%v", decoded[0])
	}
	if decoded[1].Key != ":path" || decoded[1].Value != "/sample/path" {
		t.Fatalf("Error DecodeHeader: want=:path, /sample/path, ans=%v", decoded[0])
	}
	if con.DynamicTable[0].Key != "custom-Key" || con.DynamicTable[0].Value != "custom-header" {
		t.Fatalf("Error DecodeHeader: want=custom-Key, custom-header, ans=%v", con.DynamicTable[0])
	}
	if len(con.DynamicTable) != 1 {
		t.Fatalf("Error DecodeHeader: want=1, ans=%v", len(con.DynamicTable))
	}

	// c3.1
	encoded = []byte{0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d}
	decoded, con, _ = DecodeHeader(encoded, HpackConn{[]KeyValue{}, 4096})

	// c3.2
	encoded = []byte{0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65}
	decoded, con, _ = DecodeHeader(encoded, con)
	// c3.3
	// :method: GET
	//:scheme: https
	//:path: /index.html
	//:authority: www.example.com
	//custom-Key: custom-Value
	//
	//  [dynamic header table]
	//[  1] (s =  54) custom-Key: custom-Value
	//[  2] (s =  53) cache-control: no-cache
	//[  3] (s =  57) :authority: www.example.com
	//      Table size: 164
	encoded = []byte{0x82, 0x87, 0x85, 0xbf, 0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65}
	decoded, con, _ = DecodeHeader(encoded, con)

	if decoded[0].Key != ":method" || decoded[0].Value != "GET" ||
		decoded[1].Key != ":scheme" || decoded[1].Value != "https" ||
		decoded[2].Key != ":path" || decoded[2].Value != "/index.html" ||
		decoded[3].Key != ":authority" || decoded[3].Value != "www.example.com" ||
		decoded[4].Key != "custom-Key" || decoded[4].Value != "custom-Value" {
		t.Fatalf("Error DecodeHeader: want=::method: GET,:scheme: https,:path: /index.html,:authority: www.example.com,custom-Key: custom-Value, %v", decoded)
	}
	if con.DynamicTable[0].Key != "custom-Key" || con.DynamicTable[0].Value != "custom-Value" ||
		con.DynamicTable[1].Key != "cache-control" || con.DynamicTable[1].Value != "no-cache" ||
		con.DynamicTable[2].Key != ":authority" || con.DynamicTable[2].Value != "www.example.com" {
		t.Fatalf("Error DecodeHeader: want=:[{custom-Key custom-Value} {cache-control no-cache} {:authority www.example.com}], %v", con.DynamicTable)
	}

	// c4.1
	encoded = []byte{0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff}
	decoded, con, _ = DecodeHeader(encoded, HpackConn{[]KeyValue{}, 4096})
	if decoded[0].Key != ":method" || decoded[0].Value != "GET" ||
		decoded[1].Key != ":scheme" || decoded[1].Value != "http" ||
		decoded[2].Key != ":path" || decoded[2].Value != "/" ||
		decoded[3].Key != ":authority" || decoded[3].Value != "www.example.com" {
		t.Fatalf("Error DecodeHeader: want=:[{:method GET} {:scheme http} {:path /} {:authority www.example.com}], %v", decoded)
	}
	if con.DynamicTable[0].Key != ":authority" || con.DynamicTable[0].Value != "www.example.com" {
		t.Fatalf("Error DecodeHeader: want=:[{:authority: www.example.com}], %v", con.DynamicTable)
	}

	// c6.1
	encoded = []byte{0x48, 0x82, 0x64, 0x02, 0x58, 0x85, 0xae, 0xc3, 0x77, 0x1a, 0x4b, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff, 0x6e, 0x91, 0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8, 0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3}
	decoded, con, _ = DecodeHeader(encoded, HpackConn{[]KeyValue{}, 4096})

	if decoded[0].Key != ":status" || decoded[0].Value != "302" ||
		decoded[1].Key != "cache-control" || decoded[1].Value != "private" ||
		decoded[2].Key != "date" || decoded[2].Value != "Mon, 21 Oct 2013 20:13:21 GMT" ||
		decoded[3].Key != "location" || decoded[3].Value != "https://www.example.com" {
		t.Fatalf("Error DecodeHeader: want=:[{:status 302} {cache-control private} {date Mon, 21 Oct 2013 20:13:21 GMT} {location https://www.example.com}], %v", decoded)
	}
	if con.DynamicTable[0].Key != "location" || con.DynamicTable[0].Value != "https://www.example.com" ||
		con.DynamicTable[1].Key != "date" || con.DynamicTable[1].Value != "Mon, 21 Oct 2013 20:13:21 GMT" ||
		con.DynamicTable[2].Key != "cache-control" || con.DynamicTable[2].Value != "private" ||
		con.DynamicTable[3].Key != ":status" || con.DynamicTable[3].Value != "302" {
		t.Fatalf("Error DecodeHeader: want=[{location https://www.example.com} {date Mon, 21 Oct 2013 20:13:21 GMT} {cache-control private} {:status 302}], %v", con.DynamicTable)
	}

	// c6.1 + limit (len(location+https://www.example.com)+32=63)
	encoded = []byte{0x48, 0x82, 0x64, 0x02, 0x58, 0x85, 0xae, 0xc3, 0x77, 0x1a, 0x4b, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0, 0x82, 0xa6, 0x2d, 0x1b, 0xff, 0x6e, 0x91, 0x9d, 0x29, 0xad, 0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8, 0xe9, 0xae, 0x82, 0xae, 0x43, 0xd3}
	decoded, con, _ = DecodeHeader(encoded, HpackConn{[]KeyValue{}, 63})
	if len(con.DynamicTable) != 1 {
		t.Fatalf("Error DecodeHeader: want=1, ans=%v", len(con.DynamicTable))
	}

	decoded, con, _ = DecodeHeader(encoded, HpackConn{[]KeyValue{}, 62})
	if len(con.DynamicTable) != 0 {
		t.Fatalf("Error DecodeHeader: want=0, ans=%v", len(con.DynamicTable))
	}

}

func TestEncodeHeader(t *testing.T) {
	// c.4.1
	plain := []KeyValue{
		KeyValue{":method", "GET"},
		KeyValue{":scheme", "http"},
		KeyValue{":path", "/"},
		KeyValue{":authority", "www.example.com"},
	}
	b, con, _ := EncodeHeader(plain, HpackConn{[]KeyValue{}, 4096})
	bHex := fmt.Sprintf("%#x", b)
	if bHex != "0x828684418cf1e3c2e5f23a6ba0ab90f4ff" {
		t.Fatalf("Error EncodeHeader: want=0x828684418cf1e3c2e5f23a6ba0ab90f4ff, ans=%v", bHex)
	}

	// c.4.2
	plain = []KeyValue{
		KeyValue{":method", "GET"},
		KeyValue{":scheme", "http"},
		KeyValue{":path", "/"},
		KeyValue{":authority", "www.example.com"},
		KeyValue{"cache-control", "no-cache"},
	}
	b, con, _ = EncodeHeader(plain, con)
	bHex = fmt.Sprintf("%#x", b)
	if bHex != "0x828684be5886a8eb10649cbf" {
		t.Fatalf("Error EncodeHeader: want=0x828684be5886a8eb10649cbf, ans=%v", bHex)
	}

	// c.4.3
	plain = []KeyValue{
		KeyValue{":method", "GET"},
		KeyValue{":scheme", "https"},
		KeyValue{":path", "/index.html"},
		KeyValue{":authority", "www.example.com"},
		KeyValue{"custom-Key", "custom-Value"},
	}

	tmpCon := con
	b, con, _ = EncodeHeader(plain, tmpCon)
	dh := con.DynamicTable
	bHex = fmt.Sprintf("%#x", b)
	if bHex != "0x828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf" {
		t.Fatalf("Error EncodeHeader: want=0x828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf, ans=%v", bHex)
	}
	if dh[0].Key != "custom-Key" || dh[0].Value != "custom-Value" ||
		dh[1].Key != "cache-control" || dh[1].Value != "no-cache" ||
		dh[2].Key != ":authority" || dh[2].Value != "www.example.com" {
		t.Fatalf("Error EncodeHeader: want=[{custom-Key custom-Value} {cache-control no-cache} {:authority www.example.com}], ans=%v", dh)
	}

	// c.4.3 + limit
	tmpCon.TableSizeLimit = 106
	_, con, _ = EncodeHeader(plain, tmpCon)
	if len(con.DynamicTable) != 1 {
		t.Fatalf("Error DecodeHeader: want=1, ans=%v", len(dh))
	}

	tmpCon.TableSizeLimit = 107
	_, con, _ = EncodeHeader(plain, tmpCon)
	if len(con.DynamicTable) != 2 {
		t.Fatalf("Error DecodeHeader: want=1, ans=%v", len(dh))
	}
}
