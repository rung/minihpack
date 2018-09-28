package hpack

import (
	"bytes"
	"errors"
	"strings"
	"net/http"
)

// hpackの実装
// 方針
//  バイナリフレーム実装する done
//  ハフマン実装する(map利用) done
//  テーブル実装する done
//  read/write実装する done
//  テーブルの状態を保管しておかないといけないけどどこに保管しておこう。
//  コネクションごとにもたせる？
// 今はDropping pointをうまく表現できていない done
// 動的サイズ更新もやらなきゃいけない
//  →引数と返値が多すぎる。structでまとめる・・・？
// やるなら下記みたいな感じ。
// type struct Connection {
//	SendDynamicTable []KeyValue
//  ReceiveDynamicTable []KeyValue
//  TableSizeLimit int
//  }

// テーブルの実装
//         <----------  Index Address Space ---------->
//        <-- Static  Table -->  <-- Dynamic Table -->
//        +---+-----------+---+  +---+-----------+---+
//        | 1 |    ...    | s |  |s+1|    ...    |s+k|
//        +---+-----------+---+  +---+-----------+---+
//                               ^                   |
//                               |                   V
//                        Insertion Point      Dropping Point

// EncodeHeader
//  return: encodedHeader, dynamicHeader, error
func EncodeHeaderFromRequest(request *http.Request, con HpackConn) ([]byte, HpackConn, error) {
	kv := []KeyValue{}
	kv = append(kv, KeyValue{":method", request.Method})
	kv = append(kv, KeyValue{":scheme", "https"})
	kv = append(kv, KeyValue{":path", request.RequestURI})
	kv = append(kv, KeyValue{":authority", request.Host})
	for k, vl := range request.Header{
		for _, v := range vl {
			kv = append(kv, KeyValue{k, v})
		}
	}

	return EncodeHeader(kv, con)

}

func EncodeHeader(plainHeader []KeyValue, con HpackConn) ([]byte, HpackConn, error) {
	dynamicHeader := con.DynamicTable
	limit := con.TableSizeLimit

	plainBuffer := plainHeader
	encBuffer := []byte{}

	for {
		//enco
		if strings.ToLower(plainBuffer[0].Key) != "cookie" && strings.ToLower(plainBuffer[0].Key) != "set-cookie" {
			// not cookie
			nhF, koF, index := searchHeaderTable(dynamicHeader, &plainBuffer[0])
			if nhF == true {
				// Not hit
				//  0   1   2   3   4   5   6   7
				//+---+---+---+---+---+---+---+---+
				//| 0 | 1 |           0           |
				//+---+---+-----------------------+
				//| H |     Name Length (7+)      |
				//+---+---------------------------+
				//|  Name String (Length octets)  |
				//+---+---------------------------+
				//| H |     Value Length (7+)     |
				//+---+---------------------------+
				//| Value String (Length octets)  |
				//+-------------------------------+
				b := []byte{64}
				// use huffman
				b, err := encodeStrings(b, plainBuffer[0].Key, true)
				if err != nil {
					return nil, HpackConn{}, err
				}
				b, err = encodeStrings(b, plainBuffer[0].Value, true)
				if err != nil {
					return nil, HpackConn{}, err
				}

				encBuffer = append(encBuffer, b...)

				if len(dynamicHeader) > 0 {
					dynamicHeader = append(dynamicHeader[0:1], dynamicHeader[0:]...)
					dynamicHeader[0] = plainBuffer[0]
				} else {
					dynamicHeader = append(dynamicHeader, plainBuffer[0])
				}

			} else if koF == true {
				// Hit a Key Only
				//  0   1   2   3   4   5   6   7
				//+---+---+---+---+---+---+---+---+
				//| 0 | 1 |      Index (6+)       |
				//+---+---+-----------------------+
				//| H |     Value Length (7+)     |
				//+---+---------------------------+
				//| Value String (Length octets)  |
				//+-------------------------------+

				b, err := encodeIntValue([]byte{64}, 6, uint64(index))
				if err != nil {
					return nil, HpackConn{}, err
				}
				b, err = encodeStrings(b, plainBuffer[0].Value, true)
				if err != nil {
					return nil, HpackConn{}, err
				}
				encBuffer = append(encBuffer, b...)

				if len(dynamicHeader) > 0 {
					dynamicHeader = append(dynamicHeader[0:1], dynamicHeader[0:]...)
					dynamicHeader[0] = plainBuffer[0]
				} else {
					dynamicHeader = append(dynamicHeader, plainBuffer[0])
				}
			} else {
				// Hit a Key & Value
				// Index header field
				//  0   1   2   3   4   5   6   7
				//+---+---+---+---+---+---+---+---+
				//| 1 |        Index (7+)         |
				//+---+---------------------------+
				b, err := encodeIntValue([]byte{128}, 7, uint64(index))
				if err != nil {
					return nil, HpackConn{}, err
				}
				encBuffer = append(encBuffer, b...)
			}

		} else {
			// Cookie
			//      0   1   2   3   4   5   6   7
			//   +---+---+---+---+---+---+---+---+
			//   | 0 | 0 | 0 | 1 |  Index (4+)   |
			//   +---+---+-----------------------+
			//   | H |     Value Length (7+)     |
			//   +---+---------------------------+
			//   | Value String (Length octets)  |
			//   +-------------------------------+

			// Cookie Index == 32
			// Set-cookie Index == 55
			var b []byte
			if strings.ToLower(plainBuffer[0].Key) == "cookie" {
				by, err := encodeIntValue([]byte{10}, 4, 32)
				if err != nil {
					return nil, HpackConn{}, err
				}
				b = by
			} else {
				by, err := encodeIntValue([]byte{10}, 4, 55)
				if err != nil {
					return nil, HpackConn{}, err
				}
				b = by
			}
			b, err := encodeStrings(b, plainBuffer[0].Value, true)
			if err != nil {
				return nil, HpackConn{}, err
			}
			encBuffer = append(encBuffer, b...)
		}

		// forloop conditions
		if len(plainBuffer) != 1 {
			plainBuffer = plainBuffer[1:]
		} else {
			break
		}
	}

	dynamicHeader = cutHeader(dynamicHeader, int(limit))
	return encBuffer, HpackConn{dynamicHeader, limit}, nil
}

// DecodeHeader
//  encoded bytes
//   return: decodedHeader, dynamicHeader, error
func DecodeHeader(encoded []byte, con HpackConn) ([]KeyValue, HpackConn, error) {
	dynamicHeader := con.DynamicTable
	limit := con.TableSizeLimit

	//dHeader
	headerBuffer := []KeyValue{}
	encBuffer := encoded

	for len(encBuffer) != 0 {
		// index header field
		if encBuffer[0]&128 == 128 {
			// Index header field
			//  0   1   2   3   4   5   6   7
			//+---+---+---+---+---+---+---+---+
			//| 1 |        Index (7+)         |
			//+---+---------------------------+
			i, eB, err := decodeIntValue(encBuffer, 7)
			encBuffer = eB
			if err != nil {
				return nil, HpackConn{}, err
			}
			kv, err := decodeHeaderTable(uint16(i), dynamicHeader)
			if err != nil {
				return nil, HpackConn{}, err
			}
			headerBuffer = append(headerBuffer, *kv)
		} else if encBuffer[0]&192 == 64 {
			//// 6.2.1 インデックス更新を伴うリテラルヘッダフィールド
			if encBuffer[0]&63 == 0 {
				// Index == 0
				//  0   1   2   3   4   5   6   7
				//+---+---+---+---+---+---+---+---+
				//| 0 | 1 |           0           |
				//+---+---+-----------------------+
				//| H |     Name Length (7+)      |
				//+---+---------------------------+
				//|  Name String (Length octets)  |
				//+---+---------------------------+
				//| H |     Value Length (7+)     |
				//+---+---------------------------+
				//| Value String (Length octets)  |
				//+-------------------------------+
				key, eB, err := decodeStrings(encBuffer[1:])
				encBuffer = eB
				if err != nil {
					return nil, HpackConn{}, err
				}
				value, eB, err := decodeStrings(encBuffer)
				encBuffer = eB
				if err != nil {
					return nil, HpackConn{}, err
				}
				headerBuffer = append(headerBuffer, KeyValue{key, value})
				if len(dynamicHeader) > 0 {
					dynamicHeader = append(dynamicHeader[:1], dynamicHeader[0:]...)
					dynamicHeader[0] = KeyValue{key, value}
				} else {
					dynamicHeader = append(dynamicHeader, KeyValue{key, value})
				}
			} else {
				// Index != 0
				//  0   1   2   3   4   5   6   7
				//+---+---+---+---+---+---+---+---+
				//| 0 | 1 |      Index (6+)       |
				//+---+---+-----------------------+
				//| H |     Value Length (7+)     |
				//+---+---------------------------+
				//| Value String (Length octets)  |
				//+-------------------------------+
				i, eB, err := decodeIntValue(encBuffer, 6)
				encBuffer = eB
				if err != nil {
					return nil, HpackConn{}, err
				}
				kv, err := decodeHeaderTable(uint16(i), dynamicHeader)
				if err != nil {
					return nil, HpackConn{}, err
				}
				value, eB, err := decodeStrings(encBuffer)
				encBuffer = eB
				if err != nil {
					return nil, HpackConn{}, err
				}
				headerBuffer = append(headerBuffer, KeyValue{kv.Key, value})
				if len(dynamicHeader) > 0 {
					dynamicHeader = append(dynamicHeader[:1], dynamicHeader[0:]...)
					dynamicHeader[0] = KeyValue{kv.Key, value}
				} else {
					dynamicHeader = append(dynamicHeader, KeyValue{kv.Key, value})
				}
			}
		} else if encBuffer[0]&240 == 0 || encBuffer[0]&240 == 16 {
			if encBuffer[0]&15 == 0 {
				// Index = 0
				//  0   1   2   3   4   5   6   7
				//+---+---+---+---+---+---+---+---+
				//| 0 | 0 | 0 | 0 |       0       |
				//+---+---+-----------------------+
				//| H |     Name Length (7+)      |
				//+---+---------------------------+
				//|  Name String (Length octets)  |
				//+---+---------------------------+
				//| H |     Value Length (7+)     |
				//+---+---------------------------+
				//| Value String (Length octets)  |
				//+-------------------------------+
				key, eB, err := decodeStrings(encBuffer[1:])
				encBuffer = eB
				if err != nil {
					return nil, HpackConn{}, err
				}
				value, eB, err := decodeStrings(encBuffer)
				encBuffer = eB
				if err != nil {
					return nil, HpackConn{}, err
				}
				headerBuffer = append(headerBuffer, KeyValue{key, value})

			} else {
				// Index != 0
				//  0   1   2   3   4   5   6   7
				//+---+---+---+---+---+---+---+---+
				//| 0 | 0 | 0 | 0 |  Index (4+)   |
				//+---+---+-----------------------+
				//| H |     Value Length (7+)     |
				//+---+---------------------------+
				//| Value String (Length octets)  |
				//+-------------------------------+
				i, eB, err := decodeIntValue(encBuffer, 4)
				encBuffer = eB
				if err != nil {
					return nil, HpackConn{}, err
				}
				kv, err := decodeHeaderTable(uint16(i), dynamicHeader)
				if err != nil {
					return nil, HpackConn{}, err
				}
				value, eB, err := decodeStrings(encBuffer)
				encBuffer = eB
				if err != nil {
					return nil, HpackConn{}, err
				}
				headerBuffer = append(headerBuffer, KeyValue{kv.Key, value})
			}
		} else if encBuffer[0]&224 == 32 {
			// not correspond!
			// Dynamic Table Size Update
			// 0   1   2   3   4   5   6   7
			// +---+---+---+---+---+---+---+---+
			// | 0 | 0 | 1 |   Max size (5+)   |
			// +---+---------------------------+
			i, eB, err := decodeIntValue(encBuffer, 5)
			encBuffer = eB
			if err != nil {
				return nil, HpackConn{}, err
			}
			limit = uint32(i)
		} else {
			return nil, HpackConn{}, errors.New("DecodeHeader: can't decode")
		}
	}

	dynamicHeader = cutHeader(dynamicHeader, int(limit))
	return headerBuffer, HpackConn{dynamicHeader, limit}, nil
}

// エンコード時のテーブル格納は同時実施しない？今の実装はおかしいと思われる.
// return: NotHitFlag, HitKeyOnlyFlag, dynamicHeaderTable, hitInt
func searchHeaderTable(dHeaderTable []KeyValue, plain *KeyValue) (bool, bool, int) {
	// Hit the dynamic header table
	for c, v := range dHeaderTable {
		if v.Key == plain.Key && v.Value == plain.Value {
			return false, false, c + 62
		}
	}
	// Hit the static header table
	for c, v := range staticHeaderTable {
		if v.Key == plain.Key && v.Value == plain.Value {
			return false, false, c + 1
		}
	}
	// Hit the dynamic header table(Key only)
	for c, v := range dHeaderTable {
		if v.Key == plain.Key {
			dHeaderTable = append(dHeaderTable, *plain)
			return false, true, c + 62
		}
	}
	// Hit the static header table(Key only)
	for c, v := range staticHeaderTable {
		if v.Key == plain.Key {
			return false, true, c + 1
		}
	}
	// Not hit
	return true, false, 0

}

// デコード時にはテーブル格納はしない
func decodeHeaderTable(idx uint16, dHeaderTable []KeyValue) (*KeyValue, error) {
	if idx <= 0 || idx > uint16(61+len(dHeaderTable)) {
		return nil, errors.New("decoderHeaderTable: wrong idx")
	}
	// static table
	if idx < 62 {
		v := staticHeaderTable[idx-1]
		return &v, nil
	}
	// dynamic table
	v := dHeaderTable[idx-62]
	return &v, nil
}

// Decode Int Value
// 整数表現
//  0   1   2   3   4   5   6   7
//+---+---+---+---+---+---+---+---+
//| ? | ? | ? | 1   1   1   1   1 |
//+---+---+---+-------------------+
//| 1 |    Value-(2^N-1) LSB      |
//+---+---------------------------+
//               ...
//+---+---------------------------+
//| 0 |    Value-(2^N-1) MSB      |
//+---+---------------------------+
//
// decode I from the next N bits
//if I < 2^N - 1, return I
//else
//    M = 0
//    repeat
//        B = next octet
//        I = I + (B & 127) * 2^M
//        M = M + 7
//    while B & 128 == 128
//    return I
// decoder
//  名前のインデックス、ヘッダフィールドのインデックスまたは文字列の長さを表現するために使用されます。
func decodeIntValue(original []byte, n uint8) (value uint64, remain []byte, err error) {
	// validate n
	if n > 8 {
		return 0, nil, errors.New("bad n")
	}
	// if I < 2^N - 1, return I
	i := uint64((original[0]) & (1<<n - 1))
	if i < (1<<n - 1) {
		return i, original[1:], nil
	}

	// if I >= 2^N - 1
	tmp := uint64(1<<n - 1)
	m := uint64(0)
	for bi := 1; ; bi++ {
		b := original[bi]
		bv := uint64(b & byte(127))
		tmp += (bv << m)
		if (b & byte(128)) == 0 {
			return tmp, original[bi+1:], nil
		}
		m += 7
	}
}

//Encode Int Value
func encodeIntValue(original []byte, n uint8, value uint64) (after []byte, err error) {
	if n > 8 {
		return nil, errors.New("bad n")
	}

	// if I < 2^N -1
	if value < (1<<n - 1) {
		original[len(original)-1] |= uint8(value)
		return original, nil
	}

	// I => 2^N -1
	original[len(original)-1] |= uint8(1<<n - 1)
	v := value - (1<<n - 1)

	for {
		if v < 127 {
			after = append(after, byte(v&127))
			return append(original, after...), nil
		}
		after = append(after, byte((v&127)|128))
		v = v >> 7
	}
}

// 5.2.  String Literal Representation
//   0   1   2   3   4   5   6   7
//+---+---+---+---+---+---+---+---+
//| H |    String Length (7+)     |
//+---+---------------------------+
//|  String Data (Length octets)  |
//+-------------------------------+
func decodeStrings(original []byte) (value string, remain []byte, err error) {
	// huffman encoded
	l, rb, err := decodeIntValue(original, 7)

	if (original[0] & 128) == 128 {
		encoded := rb[:l]
		decoded, err := decodeHuffmanStrings(encoded)
		if err != nil {
			return "", nil, err
		}
		return decoded, rb[l:], nil
	}

	if err != nil {
		return "", nil, err
	}
	v := string(rb[:l])

	// not encoded (just ascii)
	return v, rb[l:], nil
}

func encodeStrings(original []byte, str string, huf bool) (encoded []byte, err error) {
	// huf encode
	if huf == true {
		var bin []Bin
		for _, b := range []byte(str) {
			bin = append(bin, huffmanEncodeTable[b]...)
		}

		enc := BinToByte(bin)
		by := append(original, byte(128))
		by, err := encodeIntValue(by, 7, uint64(len(enc)))
		if err != nil {
			return nil, err
		}
		by = append(by, enc...)
		return by, nil
	}

	// not encode
	b := append(original, byte(0))
	b, err = encodeIntValue(b, 7, uint64(len(str)))
	if err != nil {
		return nil, err
	}
	b = append(b, []byte(str)...)
	return b, nil
}

func decodeHuffmanStrings(encoded []byte) (string, error) {
	// []byte 11100000
	//        11011111
	//        00001000
	// string list
	strByte := &bytes.Buffer{}

	// convert Bin format
	binlist := ByteToBin(encoded)

	// decode Huffman
	// minimum length : 5
	// maximum length : 30
	// Cur
	// sChar
	sChar := 0
	for cur := 4; cur < len(binlist)+1; cur++ {
		b := BinToUint32(binlist[sChar:cur])
		codelen := cur - sChar
		v, ok := huffmanDecodeTable[b]
		if ok {
			if v.codeLen == codelen {
				strByte.WriteByte(v.b)
				sChar = cur
				continue
			}
		}
		if cur-sChar > 30 {
			err := errors.New("failed to decode huffman strings (can't find string)")
			return "", err
		}
	}
	if len(binlist[sChar:]) > 7 {
		err := errors.New("failed to decode huffman strings (too much eos)")
		return "", err
	}
	for _, bit := range binlist[sChar:len(binlist)] {
		if bit == Zero {
			err := errors.New("failed to decode huffman strings (wrong eos)")
			return "", err
		}
	}
	return string(strByte.Bytes()), nil
}
