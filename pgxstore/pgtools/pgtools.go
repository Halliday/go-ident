package pgtools

import (
	"encoding/binary"
	"fmt"

	"github.com/jackc/pgtype"
)

type ArrayDecoder struct {
	ci  *pgtype.ConnInfo
	src []byte
	Len int
}

func NewArrayDecoder(ci *pgtype.ConnInfo, src []byte) (a ArrayDecoder, err error) {
	var arrayHeader pgtype.ArrayHeader
	rp, err := arrayHeader.DecodeBinary(ci, src)
	if err != nil {
		return a, err
	}

	var l = 0
	if len(arrayHeader.Dimensions) > 0 {
		l = int(arrayHeader.Dimensions[0].Length)
		for _, d := range arrayHeader.Dimensions[1:] {
			l *= int(d.Length)
		}
	}

	return ArrayDecoder{ci, src[rp:], l}, nil
}

func (a *ArrayDecoder) Decode(item pgtype.BinaryDecoder) (err error) {
	a.Len--
	l := int(int32(binary.BigEndian.Uint32(a.src)))
	a.src = a.src[4:]
	var src []byte
	if l >= 0 {
		src = a.src[:l]
		a.src = a.src[l:]
	}
	return item.DecodeBinary(a.ci, src)
}

func (a *ArrayDecoder) Next() bool {
	return a.Len > 0
}

func ScanDecoders(ci *pgtype.ConnInfo, src []byte, decoders ...pgtype.BinaryDecoder) error {
	scanner := pgtype.NewCompositeBinaryScanner(ci, src)
	l := scanner.FieldCount()
	if l != len(decoders) {
		return fmt.Errorf("bad record field count: expected %d, got %d", len(decoders), l)
	}

	for i := 0; scanner.Next(); i++ {
		binaryDecoder := decoders[i]
		if err := binaryDecoder.DecodeBinary(ci, scanner.Bytes()); err != nil {
			return fmt.Errorf("record field %d: %w", i, err)
		}
	}

	return scanner.Err()
}
