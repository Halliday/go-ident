package pgxstore

import (
	"strconv"
	"strings"

	"github.com/halliday/go-ident"
	"github.com/jackc/pgx/v4"
)

var pgxResultFormatsBinary = pgx.QueryResultFormats{pgx.BinaryFormatCode}

type pgxBuilder struct {
	strings.Builder
	numArgs int
	args    []any
}

func (b *pgxBuilder) resultFormatsBinary() {
	if len(b.args) != 0 {
		panic("resultFormatsBinary must be called before any WriteValue")
	}
	b.args = append(b.args, pgxResultFormatsBinary)
}

func (b *pgxBuilder) WriteValue(v any) string {
	b.args = append(b.args, v)
	b.numArgs++
	s := "$" + strconv.Itoa(b.numArgs)
	b.WriteString(s)
	return s
}

func (b *pgxBuilder) WriteSelection(sel ident.Selection) (hasWhere bool) {
	if sel.All {
		if len(sel.Ids) != 0 {
			b.WriteString(` WHERE id != ANY(`)
			b.WriteValue(sel.Ids)
			b.WriteString(")")
			return true
		}
	} else {
		b.WriteString(` WHERE id = ANY(`)
		b.WriteValue(sel.Ids)
		b.WriteString(")")
		return true
	}
	return false
}
