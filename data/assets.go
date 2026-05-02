package data

import "embed"

//go:embed gtfobins.json defaults.json remediations.json
var Files embed.FS
