package version

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var source string

var Version = strings.TrimSpace(source)
