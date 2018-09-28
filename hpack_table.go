package hpack

// Hpack Connection State Struct
type HpackConn struct {
	DynamicTable   []KeyValue
	TableSizeLimit uint32
}

// Header type
type KeyValue struct {
	Key   string
	Value string
}

func cutHeader(kvSlice []KeyValue, limit int) []KeyValue {
	i := 0
	for c, kv := range kvSlice {
		i += len(kv.Key)
		i += len(kv.Value)
		i += 32
		if i > limit {
			return kvSlice[0:c]
		}
	}
	return kvSlice
}

// Bin is a type for represent a binary(0 or 1).
type Bin bool

const (
	One  Bin = true
	Zero Bin = false
)

func BinToByte(bi []Bin) []byte {
	var dst []byte
	var buffer byte
	c := 0
	var cur uint8
	for _, b := range bi {
		cur = uint8(c % 8)
		if c != 0 && cur == 0 {
			dst = append(dst, buffer)
			buffer = byte(0)
		}
		if b == One {
			buffer |= 1 << (7 - cur)
		} else {
			buffer |= 0 << (7 - cur)
		}
		c++
	}
	if cur == 7 {
		dst = append(dst, buffer)
		return dst
	} else {
		for i := cur; i < 7; i++ {
			buffer |= 1 << (6 - i)
		}
		dst = append(dst, buffer)
	}

	return dst
}

func ByteToBin(encoded []byte) []Bin {
	var binlist []Bin
	for _, b := range encoded {
		for i := uint8(0); i < 8; i++ {
			if (b<<i)&128 == 128 {
				binlist = append(binlist, One)
			} else {
				binlist = append(binlist, Zero)
			}
		}
	}
	return binlist
}

func BinToUint32(binlist []Bin) uint32 {
	var value uint32
	for _, b := range binlist {
		if b == One {
			value += 1
		}
		value = value << 1
	}
	value = value >> 1
	return value
}

var staticHeaderTable [61]KeyValue = [61]KeyValue{
	KeyValue{Key: ":authority"},
	KeyValue{Key: ":method", Value: "GET"},
	KeyValue{Key: ":method", Value: "POST"},
	KeyValue{Key: ":path", Value: "/"},
	KeyValue{Key: ":path", Value: "/index.html"},
	KeyValue{Key: ":scheme", Value: "http"},
	KeyValue{Key: ":scheme", Value: "https"},
	KeyValue{Key: ":status", Value: "200"},
	KeyValue{Key: ":status", Value: "204"},
	KeyValue{Key: ":status", Value: "206"},
	KeyValue{Key: ":status", Value: "304"},
	KeyValue{Key: ":status", Value: "400"},
	KeyValue{Key: ":status", Value: "404"},
	KeyValue{Key: ":status", Value: "500"},
	KeyValue{Key: "accept-charset"},
	KeyValue{Key: "accept-encoding", Value: "gzip, deflate"},
	KeyValue{Key: "accept-language"},
	KeyValue{Key: "accept-ranges"},
	KeyValue{Key: "accept"},
	KeyValue{Key: "access-control-allow-origin"},
	KeyValue{Key: "age"},
	KeyValue{Key: "allow"},
	KeyValue{Key: "authorization"},
	KeyValue{Key: "cache-control"},
	KeyValue{Key: "content-disposition"},
	KeyValue{Key: "content-encoding"},
	KeyValue{Key: "content-language"},
	KeyValue{Key: "content-length"},
	KeyValue{Key: "content-location"},
	KeyValue{Key: "content-range"},
	KeyValue{Key: "content-type"},
	KeyValue{Key: "cookie"},
	KeyValue{Key: "date"},
	KeyValue{Key: "etag"},
	KeyValue{Key: "expect"},
	KeyValue{Key: "expires"},
	KeyValue{Key: "from"},
	KeyValue{Key: "host"},
	KeyValue{Key: "if-match"},
	KeyValue{Key: "if-modified-since"},
	KeyValue{Key: "if-none-match"},
	KeyValue{Key: "if-range"},
	KeyValue{Key: "if-unmodified-since"},
	KeyValue{Key: "last-modified"},
	KeyValue{Key: "link"},
	KeyValue{Key: "location"},
	KeyValue{Key: "max-forwards"},
	KeyValue{Key: "proxy-authenticate"},
	KeyValue{Key: "proxy-authorization"},
	KeyValue{Key: "range"},
	KeyValue{Key: "referer"},
	KeyValue{Key: "refresh"},
	KeyValue{Key: "retry-after"},
	KeyValue{Key: "server"},
	KeyValue{Key: "set-cookie"},
	KeyValue{Key: "strict-transport-security"},
	KeyValue{Key: "transfer-encoding"},
	KeyValue{Key: "user-agent"},
	KeyValue{Key: "vary"},
	KeyValue{Key: "via"},
	KeyValue{Key: "www-authenticate"},
}

// huffman table
type huffman struct {
	b       byte
	codeLen int
}

var huffmanEncodeTable map[byte][]Bin = map[byte][]Bin{
	byte(0):   []Bin{One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero},
	byte(1):   []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, Zero, Zero},
	byte(2):   []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One, Zero},
	byte(3):   []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One, One},
	byte(4):   []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero, Zero},
	byte(5):   []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero, One},
	byte(6):   []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One, Zero},
	byte(7):   []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One, One},
	byte(8):   []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero, Zero},
	byte(9):   []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, Zero},
	byte(10):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero},
	byte(11):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero, One},
	byte(12):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, Zero},
	byte(13):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One},
	byte(14):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, One},
	byte(15):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, Zero},
	byte(16):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, One},
	byte(17):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, Zero},
	byte(18):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, One},
	byte(19):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, Zero},
	byte(20):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One},
	byte(21):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero},
	byte(22):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero},
	byte(23):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One},
	byte(24):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero},
	byte(25):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One},
	byte(26):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero},
	byte(27):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One},
	byte(28):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero},
	byte(29):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One},
	byte(30):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero},
	byte(31):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One},
	byte(32):  []Bin{Zero, One, Zero, One, Zero, Zero},
	byte(33):  []Bin{One, One, One, One, One, One, One, Zero, Zero, Zero},
	byte(34):  []Bin{One, One, One, One, One, One, One, Zero, Zero, One},
	byte(35):  []Bin{One, One, One, One, One, One, One, One, One, Zero, One, Zero},
	byte(36):  []Bin{One, One, One, One, One, One, One, One, One, One, Zero, Zero, One},
	byte(37):  []Bin{Zero, One, Zero, One, Zero, One},
	byte(38):  []Bin{One, One, One, One, One, Zero, Zero, Zero},
	byte(39):  []Bin{One, One, One, One, One, One, One, One, Zero, One, Zero},
	byte(40):  []Bin{One, One, One, One, One, One, One, Zero, One, Zero},
	byte(41):  []Bin{One, One, One, One, One, One, One, Zero, One, One},
	byte(42):  []Bin{One, One, One, One, One, Zero, Zero, One},
	byte(43):  []Bin{One, One, One, One, One, One, One, One, Zero, One, One},
	byte(44):  []Bin{One, One, One, One, One, Zero, One, Zero},
	byte(45):  []Bin{Zero, One, Zero, One, One, Zero},
	byte(46):  []Bin{Zero, One, Zero, One, One, One},
	byte(47):  []Bin{Zero, One, One, Zero, Zero, Zero},
	byte(48):  []Bin{Zero, Zero, Zero, Zero, Zero},
	byte(49):  []Bin{Zero, Zero, Zero, Zero, One},
	byte(50):  []Bin{Zero, Zero, Zero, One, Zero},
	byte(51):  []Bin{Zero, One, One, Zero, Zero, One},
	byte(52):  []Bin{Zero, One, One, Zero, One, Zero},
	byte(53):  []Bin{Zero, One, One, Zero, One, One},
	byte(54):  []Bin{Zero, One, One, One, Zero, Zero},
	byte(55):  []Bin{Zero, One, One, One, Zero, One},
	byte(56):  []Bin{Zero, One, One, One, One, Zero},
	byte(57):  []Bin{Zero, One, One, One, One, One},
	byte(58):  []Bin{One, Zero, One, One, One, Zero, Zero},
	byte(59):  []Bin{One, One, One, One, One, Zero, One, One},
	byte(60):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero},
	byte(61):  []Bin{One, Zero, Zero, Zero, Zero, Zero},
	byte(62):  []Bin{One, One, One, One, One, One, One, One, One, Zero, One, One},
	byte(63):  []Bin{One, One, One, One, One, One, One, One, Zero, Zero},
	byte(64):  []Bin{One, One, One, One, One, One, One, One, One, One, Zero, One, Zero},
	byte(65):  []Bin{One, Zero, Zero, Zero, Zero, One},
	byte(66):  []Bin{One, Zero, One, One, One, Zero, One},
	byte(67):  []Bin{One, Zero, One, One, One, One, Zero},
	byte(68):  []Bin{One, Zero, One, One, One, One, One},
	byte(69):  []Bin{One, One, Zero, Zero, Zero, Zero, Zero},
	byte(70):  []Bin{One, One, Zero, Zero, Zero, Zero, One},
	byte(71):  []Bin{One, One, Zero, Zero, Zero, One, Zero},
	byte(72):  []Bin{One, One, Zero, Zero, Zero, One, One},
	byte(73):  []Bin{One, One, Zero, Zero, One, Zero, Zero},
	byte(74):  []Bin{One, One, Zero, Zero, One, Zero, One},
	byte(75):  []Bin{One, One, Zero, Zero, One, One, Zero},
	byte(76):  []Bin{One, One, Zero, Zero, One, One, One},
	byte(77):  []Bin{One, One, Zero, One, Zero, Zero, Zero},
	byte(78):  []Bin{One, One, Zero, One, Zero, Zero, One},
	byte(79):  []Bin{One, One, Zero, One, Zero, One, Zero},
	byte(80):  []Bin{One, One, Zero, One, Zero, One, One},
	byte(81):  []Bin{One, One, Zero, One, One, Zero, Zero},
	byte(82):  []Bin{One, One, Zero, One, One, Zero, One},
	byte(83):  []Bin{One, One, Zero, One, One, One, Zero},
	byte(84):  []Bin{One, One, Zero, One, One, One, One},
	byte(85):  []Bin{One, One, One, Zero, Zero, Zero, Zero},
	byte(86):  []Bin{One, One, One, Zero, Zero, Zero, One},
	byte(87):  []Bin{One, One, One, Zero, Zero, One, Zero},
	byte(88):  []Bin{One, One, One, One, One, One, Zero, Zero},
	byte(89):  []Bin{One, One, One, Zero, Zero, One, One},
	byte(90):  []Bin{One, One, One, One, One, One, Zero, One},
	byte(91):  []Bin{One, One, One, One, One, One, One, One, One, One, Zero, One, One},
	byte(92):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, Zero},
	byte(93):  []Bin{One, One, One, One, One, One, One, One, One, One, One, Zero, Zero},
	byte(94):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero},
	byte(95):  []Bin{One, Zero, Zero, Zero, One, Zero},
	byte(96):  []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One},
	byte(97):  []Bin{Zero, Zero, Zero, One, One},
	byte(98):  []Bin{One, Zero, Zero, Zero, One, One},
	byte(99):  []Bin{Zero, Zero, One, Zero, Zero},
	byte(100): []Bin{One, Zero, Zero, One, Zero, Zero},
	byte(101): []Bin{Zero, Zero, One, Zero, One},
	byte(102): []Bin{One, Zero, Zero, One, Zero, One},
	byte(103): []Bin{One, Zero, Zero, One, One, Zero},
	byte(104): []Bin{One, Zero, Zero, One, One, One},
	byte(105): []Bin{Zero, Zero, One, One, Zero},
	byte(106): []Bin{One, One, One, Zero, One, Zero, Zero},
	byte(107): []Bin{One, One, One, Zero, One, Zero, One},
	byte(108): []Bin{One, Zero, One, Zero, Zero, Zero},
	byte(109): []Bin{One, Zero, One, Zero, Zero, One},
	byte(110): []Bin{One, Zero, One, Zero, One, Zero},
	byte(111): []Bin{Zero, Zero, One, One, One},
	byte(112): []Bin{One, Zero, One, Zero, One, One},
	byte(113): []Bin{One, One, One, Zero, One, One, Zero},
	byte(114): []Bin{One, Zero, One, One, Zero, Zero},
	byte(115): []Bin{Zero, One, Zero, Zero, Zero},
	byte(116): []Bin{Zero, One, Zero, Zero, One},
	byte(117): []Bin{One, Zero, One, One, Zero, One},
	byte(118): []Bin{One, One, One, Zero, One, One, One},
	byte(119): []Bin{One, One, One, One, Zero, Zero, Zero},
	byte(120): []Bin{One, One, One, One, Zero, Zero, One},
	byte(121): []Bin{One, One, One, One, Zero, One, Zero},
	byte(122): []Bin{One, One, One, One, Zero, One, One},
	byte(123): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero},
	byte(124): []Bin{One, One, One, One, One, One, One, One, One, Zero, Zero},
	byte(125): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, Zero, One},
	byte(126): []Bin{One, One, One, One, One, One, One, One, One, One, One, Zero, One},
	byte(127): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero},
	byte(128): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One, Zero},
	byte(129): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero, One, Zero},
	byte(130): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One, One},
	byte(131): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero, Zero},
	byte(132): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero, One, One},
	byte(133): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, Zero, Zero},
	byte(134): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, Zero, One},
	byte(135): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, Zero, One},
	byte(136): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, One, Zero},
	byte(137): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, One, Zero},
	byte(138): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, One, One},
	byte(139): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, Zero, Zero},
	byte(140): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, Zero, One},
	byte(141): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, One, Zero},
	byte(142): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, One},
	byte(143): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, One, One},
	byte(144): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, Zero},
	byte(145): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, One},
	byte(146): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, One, One},
	byte(147): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, Zero, Zero},
	byte(148): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, Zero},
	byte(149): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, Zero, One},
	byte(150): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One, Zero},
	byte(151): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One, One},
	byte(152): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero, Zero},
	byte(153): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, Zero, Zero},
	byte(154): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, Zero, Zero},
	byte(155): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero, One},
	byte(156): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, Zero, One},
	byte(157): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One, Zero},
	byte(158): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One, One},
	byte(159): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, One},
	byte(160): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, One, Zero},
	byte(161): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, Zero, One},
	byte(162): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero, One},
	byte(163): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, One, One},
	byte(164): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, Zero, Zero},
	byte(165): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero, Zero},
	byte(166): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero, One},
	byte(167): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, One, Zero},
	byte(168): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, Zero},
	byte(169): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, Zero, One},
	byte(170): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, One, Zero},
	byte(171): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, Zero},
	byte(172): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, One, One},
	byte(173): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, One, One},
	byte(174): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, One},
	byte(175): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, Zero},
	byte(176): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, Zero, Zero},
	byte(177): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, Zero, One},
	byte(178): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, Zero, Zero},
	byte(179): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One, Zero},
	byte(180): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, One},
	byte(181): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, Zero, One},
	byte(182): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, Zero},
	byte(183): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, One},
	byte(184): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, Zero},
	byte(185): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One, Zero},
	byte(186): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One, One},
	byte(187): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero, Zero},
	byte(188): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, Zero},
	byte(189): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero, One},
	byte(190): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One, Zero},
	byte(191): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One},
	byte(192): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, Zero, Zero},
	byte(193): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, Zero, One},
	byte(194): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, One},
	byte(195): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One},
	byte(196): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One, One},
	byte(197): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero},
	byte(198): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero, Zero},
	byte(199): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, Zero},
	byte(200): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One, Zero},
	byte(201): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One, One},
	byte(202): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero, Zero},
	byte(203): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, One, Zero},
	byte(204): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, One, One},
	byte(205): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero, One},
	byte(206): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One},
	byte(207): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, One},
	byte(208): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero},
	byte(209): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One, One},
	byte(210): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One, Zero},
	byte(211): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, Zero, Zero},
	byte(212): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, Zero, One},
	byte(213): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One, One},
	byte(214): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One, Zero},
	byte(215): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero},
	byte(216): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero, Zero},
	byte(217): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero, One},
	byte(218): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero, Zero},
	byte(219): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero, One},
	byte(220): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One},
	byte(221): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, One, One},
	byte(222): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero, Zero},
	byte(223): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, Zero, One},
	byte(224): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, Zero},
	byte(225): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One},
	byte(226): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, One},
	byte(227): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One, Zero},
	byte(228): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero, One},
	byte(229): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One, One},
	byte(230): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero, Zero},
	byte(231): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One},
	byte(232): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, Zero},
	byte(233): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, One},
	byte(234): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, Zero},
	byte(235): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, One},
	byte(236): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero},
	byte(237): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One},
	byte(238): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, Zero},
	byte(239): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero},
	byte(240): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, One},
	byte(241): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One, Zero},
	byte(242): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, Zero},
	byte(243): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, One},
	byte(244): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, One, One, One},
	byte(245): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero, Zero},
	byte(246): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, Zero, One},
	byte(247): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, Zero},
	byte(248): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, Zero, One, One},
	byte(249): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero},
	byte(250): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, Zero},
	byte(251): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, Zero, One},
	byte(252): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, Zero},
	byte(253): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, One},
	byte(254): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, Zero, Zero, Zero},
	byte(255): []Bin{One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, One, Zero, One, One, One, Zero},
}

var huffmanDecodeTable map[uint32]huffman = map[uint32]huffman{
	0x1ff8:     huffman{byte(0), 13},
	0x7fffd8:   huffman{byte(1), 23},
	0xfffffe2:  huffman{byte(2), 28},
	0xfffffe3:  huffman{byte(3), 28},
	0xfffffe4:  huffman{byte(4), 28},
	0xfffffe5:  huffman{byte(5), 28},
	0xfffffe6:  huffman{byte(6), 28},
	0xfffffe7:  huffman{byte(7), 28},
	0xfffffe8:  huffman{byte(8), 28},
	0xffffea:   huffman{byte(9), 24},
	0x3ffffffc: huffman{byte(10), 30},
	0xfffffe9:  huffman{byte(11), 28},
	0xfffffea:  huffman{byte(12), 28},
	0x3ffffffd: huffman{byte(13), 30},
	0xfffffeb:  huffman{byte(14), 28},
	0xfffffec:  huffman{byte(15), 28},
	0xfffffed:  huffman{byte(16), 28},
	0xfffffee:  huffman{byte(17), 28},
	0xfffffef:  huffman{byte(18), 28},
	0xffffff0:  huffman{byte(19), 28},
	0xffffff1:  huffman{byte(20), 28},
	0xffffff2:  huffman{byte(21), 28},
	0x3ffffffe: huffman{byte(22), 30},
	0xffffff3:  huffman{byte(23), 28},
	0xffffff4:  huffman{byte(24), 28},
	0xffffff5:  huffman{byte(25), 28},
	0xffffff6:  huffman{byte(26), 28},
	0xffffff7:  huffman{byte(27), 28},
	0xffffff8:  huffman{byte(28), 28},
	0xffffff9:  huffman{byte(29), 28},
	0xffffffa:  huffman{byte(30), 28},
	0xffffffb:  huffman{byte(31), 28},
	0x14:       huffman{byte(32), 6},   // ' '
	0x3f8:      huffman{byte(33), 10},  // '!'
	0x3f9:      huffman{byte(34), 10},  // '"'
	0xffa:      huffman{byte(35), 12},  // '#'
	0x1ff9:     huffman{byte(36), 13},  // '$'
	0x15:       huffman{byte(37), 6},   // '%'
	0xf8:       huffman{byte(38), 8},   // '&'
	0x7fa:      huffman{byte(39), 11},  // '''
	0x3fa:      huffman{byte(40), 10},  // '('
	0x3fb:      huffman{byte(41), 10},  // ')'
	0xf9:       huffman{byte(42), 8},   // '*'
	0x7fb:      huffman{byte(43), 11},  // '+'
	0xfa:       huffman{byte(44), 8},   // ','
	0x16:       huffman{byte(45), 6},   // '-'
	0x17:       huffman{byte(46), 6},   // '.'
	0x18:       huffman{byte(47), 6},   // '/'
	0x0:        huffman{byte(48), 5},   // '0'
	0x1:        huffman{byte(49), 5},   // '1'
	0x2:        huffman{byte(50), 5},   // '2'
	0x19:       huffman{byte(51), 6},   // '3'
	0x1a:       huffman{byte(52), 6},   // '4'
	0x1b:       huffman{byte(53), 6},   // '5'
	0x1c:       huffman{byte(54), 6},   // '6'
	0x1d:       huffman{byte(55), 6},   // '7'
	0x1e:       huffman{byte(56), 6},   // '8'
	0x1f:       huffman{byte(57), 6},   // '9'
	0x5c:       huffman{byte(58), 7},   // ':'
	0xfb:       huffman{byte(59), 8},   // ';'
	0x7ffc:     huffman{byte(60), 15},  // '<'
	0x20:       huffman{byte(61), 6},   // '='
	0xffb:      huffman{byte(62), 12},  // '>'
	0x3fc:      huffman{byte(63), 10},  // '?'
	0x1ffa:     huffman{byte(64), 13},  // '@'
	0x21:       huffman{byte(65), 6},   // 'A'
	0x5d:       huffman{byte(66), 7},   // 'B'
	0x5e:       huffman{byte(67), 7},   // 'C'
	0x5f:       huffman{byte(68), 7},   // 'D'
	0x60:       huffman{byte(69), 7},   // 'E'
	0x61:       huffman{byte(70), 7},   // 'F'
	0x62:       huffman{byte(71), 7},   // 'G'
	0x63:       huffman{byte(72), 7},   // 'H'
	0x64:       huffman{byte(73), 7},   // 'I'
	0x65:       huffman{byte(74), 7},   // 'J'
	0x66:       huffman{byte(75), 7},   // 'K'
	0x67:       huffman{byte(76), 7},   // 'L'
	0x68:       huffman{byte(77), 7},   // 'M'
	0x69:       huffman{byte(78), 7},   // 'N'
	0x6a:       huffman{byte(79), 7},   // 'O'
	0x6b:       huffman{byte(80), 7},   // 'P'
	0x6c:       huffman{byte(81), 7},   // 'Q'
	0x6d:       huffman{byte(82), 7},   // 'R'
	0x6e:       huffman{byte(83), 7},   // 'S'
	0x6f:       huffman{byte(84), 7},   // 'T'
	0x70:       huffman{byte(85), 7},   // 'U'
	0x71:       huffman{byte(86), 7},   // 'V'
	0x72:       huffman{byte(87), 7},   // 'W'
	0xfc:       huffman{byte(88), 8},   // 'X'
	0x73:       huffman{byte(89), 7},   // 'Y'
	0xfd:       huffman{byte(90), 8},   // 'Z'
	0x1ffb:     huffman{byte(91), 13},  // '['
	0x7fff0:    huffman{byte(92), 19},  // '\'
	0x1ffc:     huffman{byte(93), 13},  //
	0x3ffc:     huffman{byte(94), 14},  // '^'
	0x22:       huffman{byte(95), 6},   // '_'
	0x7ffd:     huffman{byte(96), 15},  // '`'
	0x3:        huffman{byte(97), 5},   // 'a'
	0x23:       huffman{byte(98), 6},   // 'b'
	0x4:        huffman{byte(99), 5},   // 'c'
	0x24:       huffman{byte(100), 6},  // 'd'
	0x5:        huffman{byte(101), 5},  // 'e'
	0x25:       huffman{byte(102), 6},  // 'f'
	0x26:       huffman{byte(103), 6},  // 'g'
	0x27:       huffman{byte(104), 6},  // 'h'
	0x6:        huffman{byte(105), 5},  // 'i'
	0x74:       huffman{byte(106), 7},  // 'j'
	0x75:       huffman{byte(107), 7},  // 'k'
	0x28:       huffman{byte(108), 6},  // 'l'
	0x29:       huffman{byte(109), 6},  // 'm'
	0x2a:       huffman{byte(110), 6},  // 'n'
	0x7:        huffman{byte(111), 5},  // 'o'
	0x2b:       huffman{byte(112), 6},  // 'p'
	0x76:       huffman{byte(113), 7},  // 'q'
	0x2c:       huffman{byte(114), 6},  // 'r'
	0x8:        huffman{byte(115), 5},  // 's'
	0x9:        huffman{byte(116), 5},  // 't'
	0x2d:       huffman{byte(117), 6},  // 'u'
	0x77:       huffman{byte(118), 7},  // 'v'
	0x78:       huffman{byte(119), 7},  // 'w'
	0x79:       huffman{byte(120), 7},  // 'x'
	0x7a:       huffman{byte(121), 7},  // 'y'
	0x7b:       huffman{byte(122), 7},  // 'z'
	0x7ffe:     huffman{byte(123), 15}, // '{'
	0x7fc:      huffman{byte(124), 11}, // '|'
	0x3ffd:     huffman{byte(125), 14}, // '}'
	0x1ffd:     huffman{byte(126), 13}, // '~'
	0xffffffc:  huffman{byte(127), 28},
	0xfffe6:    huffman{byte(128), 20},
	0x3fffd2:   huffman{byte(129), 22},
	0xfffe7:    huffman{byte(130), 20},
	0xfffe8:    huffman{byte(131), 20},
	0x3fffd3:   huffman{byte(132), 22},
	0x3fffd4:   huffman{byte(133), 22},
	0x3fffd5:   huffman{byte(134), 22},
	0x7fffd9:   huffman{byte(135), 23},
	0x3fffd6:   huffman{byte(136), 22},
	0x7fffda:   huffman{byte(137), 23},
	0x7fffdb:   huffman{byte(138), 23},
	0x7fffdc:   huffman{byte(139), 23},
	0x7fffdd:   huffman{byte(140), 23},
	0x7fffde:   huffman{byte(141), 23},
	0xffffeb:   huffman{byte(142), 24},
	0x7fffdf:   huffman{byte(143), 23},
	0xffffec:   huffman{byte(144), 24},
	0xffffed:   huffman{byte(145), 24},
	0x3fffd7:   huffman{byte(146), 22},
	0x7fffe0:   huffman{byte(147), 23},
	0xffffee:   huffman{byte(148), 24},
	0x7fffe1:   huffman{byte(149), 23},
	0x7fffe2:   huffman{byte(150), 23},
	0x7fffe3:   huffman{byte(151), 23},
	0x7fffe4:   huffman{byte(152), 23},
	0x1fffdc:   huffman{byte(153), 21},
	0x3fffd8:   huffman{byte(154), 22},
	0x7fffe5:   huffman{byte(155), 23},
	0x3fffd9:   huffman{byte(156), 22},
	0x7fffe6:   huffman{byte(157), 23},
	0x7fffe7:   huffman{byte(158), 23},
	0xffffef:   huffman{byte(159), 24},
	0x3fffda:   huffman{byte(160), 22},
	0x1fffdd:   huffman{byte(161), 21},
	0xfffe9:    huffman{byte(162), 20},
	0x3fffdb:   huffman{byte(163), 22},
	0x3fffdc:   huffman{byte(164), 22},
	0x7fffe8:   huffman{byte(165), 23},
	0x7fffe9:   huffman{byte(166), 23},
	0x1fffde:   huffman{byte(167), 21},
	0x7fffea:   huffman{byte(168), 23},
	0x3fffdd:   huffman{byte(169), 22},
	0x3fffde:   huffman{byte(170), 22},
	0xfffff0:   huffman{byte(171), 24},
	0x1fffdf:   huffman{byte(172), 21},
	0x3fffdf:   huffman{byte(173), 22},
	0x7fffeb:   huffman{byte(174), 23},
	0x7fffec:   huffman{byte(175), 23},
	0x1fffe0:   huffman{byte(176), 21},
	0x1fffe1:   huffman{byte(177), 21},
	0x3fffe0:   huffman{byte(178), 22},
	0x1fffe2:   huffman{byte(179), 21},
	0x7fffed:   huffman{byte(180), 23},
	0x3fffe1:   huffman{byte(181), 22},
	0x7fffee:   huffman{byte(182), 23},
	0x7fffef:   huffman{byte(183), 23},
	0xfffea:    huffman{byte(184), 20},
	0x3fffe2:   huffman{byte(185), 22},
	0x3fffe3:   huffman{byte(186), 22},
	0x3fffe4:   huffman{byte(187), 22},
	0x7ffff0:   huffman{byte(188), 23},
	0x3fffe5:   huffman{byte(189), 22},
	0x3fffe6:   huffman{byte(190), 22},
	0x7ffff1:   huffman{byte(191), 23},
	0x3ffffe0:  huffman{byte(192), 26},
	0x3ffffe1:  huffman{byte(193), 26},
	0xfffeb:    huffman{byte(194), 20},
	0x7fff1:    huffman{byte(195), 19},
	0x3fffe7:   huffman{byte(196), 22},
	0x7ffff2:   huffman{byte(197), 23},
	0x3fffe8:   huffman{byte(198), 22},
	0x1ffffec:  huffman{byte(199), 25},
	0x3ffffe2:  huffman{byte(200), 26},
	0x3ffffe3:  huffman{byte(201), 26},
	0x3ffffe4:  huffman{byte(202), 26},
	0x7ffffde:  huffman{byte(203), 27},
	0x7ffffdf:  huffman{byte(204), 27},
	0x3ffffe5:  huffman{byte(205), 26},
	0xfffff1:   huffman{byte(206), 24},
	0x1ffffed:  huffman{byte(207), 25},
	0x7fff2:    huffman{byte(208), 19},
	0x1fffe3:   huffman{byte(209), 21},
	0x3ffffe6:  huffman{byte(210), 26},
	0x7ffffe0:  huffman{byte(211), 27},
	0x7ffffe1:  huffman{byte(212), 27},
	0x3ffffe7:  huffman{byte(213), 26},
	0x7ffffe2:  huffman{byte(214), 27},
	0xfffff2:   huffman{byte(215), 24},
	0x1fffe4:   huffman{byte(216), 21},
	0x1fffe5:   huffman{byte(217), 21},
	0x3ffffe8:  huffman{byte(218), 26},
	0x3ffffe9:  huffman{byte(219), 26},
	0xffffffd:  huffman{byte(220), 28},
	0x7ffffe3:  huffman{byte(221), 27},
	0x7ffffe4:  huffman{byte(222), 27},
	0x7ffffe5:  huffman{byte(223), 27},
	0xfffec:    huffman{byte(224), 20},
	0xfffff3:   huffman{byte(225), 24},
	0xfffed:    huffman{byte(226), 20},
	0x1fffe6:   huffman{byte(227), 21},
	0x3fffe9:   huffman{byte(228), 22},
	0x1fffe7:   huffman{byte(229), 21},
	0x1fffe8:   huffman{byte(230), 21},
	0x7ffff3:   huffman{byte(231), 23},
	0x3fffea:   huffman{byte(232), 22},
	0x3fffeb:   huffman{byte(233), 22},
	0x1ffffee:  huffman{byte(234), 25},
	0x1ffffef:  huffman{byte(235), 25},
	0xfffff4:   huffman{byte(236), 24},
	0xfffff5:   huffman{byte(237), 24},
	0x3ffffea:  huffman{byte(238), 26},
	0x7ffff4:   huffman{byte(239), 23},
	0x3ffffeb:  huffman{byte(240), 26},
	0x7ffffe6:  huffman{byte(241), 27},
	0x3ffffec:  huffman{byte(242), 26},
	0x3ffffed:  huffman{byte(243), 26},
	0x7ffffe7:  huffman{byte(244), 27},
	0x7ffffe8:  huffman{byte(245), 27},
	0x7ffffe9:  huffman{byte(246), 27},
	0x7ffffea:  huffman{byte(247), 27},
	0x7ffffeb:  huffman{byte(248), 27},
	0xffffffe:  huffman{byte(249), 28},
	0x7ffffec:  huffman{byte(250), 27},
	0x7ffffed:  huffman{byte(251), 27},
	0x7ffffee:  huffman{byte(252), 27},
	0x7ffffef:  huffman{byte(253), 27},
	0x7fffff0:  huffman{byte(254), 27},
	0x3ffffee:  huffman{byte(255), 26},
}
