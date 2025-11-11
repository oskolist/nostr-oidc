//go:build dev

package web

import (
	"net/http"
	"os"
)

func getStaticFileSystem() http.FileSystem {
	return http.FS(os.DirFS("web/static"))
}
