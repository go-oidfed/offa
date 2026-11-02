package server

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-oidfed/offa/internal/model"
)

// searcherFilesystem is a http.Filesystem that looks through multiple http.
// Filesystems for a file returning the first one found
type searcherFilesystem []http.FileSystem

type searcherFile []http.File

func (sf searcherFile) collectErrors(callback func(file http.File) error) error {
	err := model.MultipleErrors{}
	for _, f := range sf {
		e := callback(f)
		if e != nil {
			err = append(err, e)
		}
	}
	if len(err) == 0 {
		err = nil
	}
	return err
}

// Close implements the http.File interface
func (sf searcherFile) Close() error {
	return sf.collectErrors(
		func(file http.File) error {
			return file.Close()
		},
	)
}

// Read implements the http.File interface
func (sf searcherFile) Read(p []byte) (n int, err error) {
	for _, f := range sf {
		buffer := make([]byte, len(p))
		n, err = f.Read(buffer)
		if err == nil {
			copy(p, buffer)
			return
		}
	}
	return
}

// Seek implements the http.File interface
func (sf searcherFile) Seek(offset int64, whence int) (i int64, e error) {
	for _, f := range sf {
		i, e = f.Seek(offset, whence)
		if e == nil {
			return
		}
	}
	return
}

// Readdir implements the http.File interface
func (sf searcherFile) Readdir(count int) (infos []fs.FileInfo, err error) {
	for _, f := range sf {
		if count > 0 && len(infos) >= count {
			break
		}
		info, e := f.Readdir(count)
		if e != nil {
			continue
		}
		for _, i := range info {
			if count > 0 && len(infos) >= count {
				break
			}
			found := false
			for _, ii := range infos {
				if i.Name() == ii.Name() {
					found = true
					break
				}
			}
			if !found {
				infos = append(infos, i)
			}
		}
	}
	return
}

// Stat implements the http.File interface
func (sf searcherFile) Stat() (i fs.FileInfo, e error) {
	for _, f := range sf {
		i, e = f.Stat()
		if e == nil {
			return
		}
	}
	return
}

// Open implements the http.FileSystem interface
func (lfs searcherFilesystem) Open(name string) (http.File, error) {
	sf := searcherFile{}
	for _, ffs := range lfs {
		if ffs == nil {
			continue
		}
		f, err := ffs.Open(name)
		if err != nil {
			continue
		}
		stat, err := f.Stat()
		if err != nil {
			continue
		}
		if stat.IsDir() {
			sf = append(sf, f)
		} else {
			return f, nil
		}
	}
	var err error
	if len(sf) == 0 {
		err = os.ErrNotExist
	}
	return sf, err
}

// httpFilesystemFS adapts an http.FileSystem to fs.FS. It is used to hand the
// searcherFilesystem (an http.FileSystem) to the fiber v3 static middleware,
// which serves from fs.FS.
type httpFilesystemFS struct {
	hfs http.FileSystem
}

// Open implements fs.FS.
func (a httpFilesystemFS) Open(name string) (fs.File, error) {
	return a.hfs.Open(name)
}

// newLocalAndOtherSearcherFilesystem creates a searcherFilesystem from a local basePath (
// if not empty) and other http.FileSystems. The local fs will be the first one.
func newLocalAndOtherSearcherFilesystem(basePath string, other ...http.FileSystem) searcherFilesystem {
	if basePath != "" {
		other = append([]http.FileSystem{http.Dir(basePath)}, other...)
	}
	return other
}

// joinIfFirstNotEmpty only joins filepaths if the first element is not empty
func joinIfFirstNotEmpty(elem ...string) string {
	if len(elem) > 0 && elem[0] != "" {
		return filepath.Join(elem...)
	}
	return ""
}
