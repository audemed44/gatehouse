// Package web embeds the built frontend (frontend/ builds into web/dist).
package web

import "embed"

//go:embed all:dist
var Dist embed.FS
