package wssec

import (
	"sort"
	"strings"
)

var attrEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	`"`, "&quot;",
	"\t", "&#x9;",
	"\n", "&#xA;",
	"\r", "&#xD;",
)

type Attr struct {
	Name  string
	Value string
}

type Form int

const (
	Document Form = iota
	Canonical
)

func renderAttrs(attrs []Attr) string {
	sorted := append([]Attr(nil), attrs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b strings.Builder
	for _, a := range sorted {
		b.WriteString(" " + a.Name + `="` + attrEscaper.Replace(a.Value) + `"`)
	}
	return b.String()
}

func EmptyElement(name string, attrs []Attr, f Form) string {
	if f == Canonical {
		return "<" + name + renderAttrs(attrs) + "></" + name + ">"
	}
	return "<" + name + renderAttrs(attrs) + "/>"
}
