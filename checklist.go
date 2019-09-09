package journal

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type Checklist struct {
	files []struct {
		path string
		hash string
	}
}

func ChecklistFromReader(in io.Reader) (*Checklist, error) {
	checklist := &Checklist{}

	r := bufio.NewReader(in)
	for {
		line, _, err := r.ReadLine()
		if err != nil {
			return nil, err
		}

		arr := strings.Split(string(line), " ")
		checklist.AddFile(arr[1], arr[0])
	}
}

func ChecklistFromDir(dir string, filter func(path string, info os.FileInfo) bool) (*Checklist, error) {
	checklist := &Checklist{}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if ok := filter(path, info); !ok {
			return nil
		}

		return checklist.Collect(path)
	})
	if err != nil {
		return nil, err
	}

	return checklist, nil
}

func (c *Checklist) AddFile(path, hash string) {
	c.files = append(c.files, struct {
		path string
		hash string
	}{path, hash})
}

func (c *Checklist) Collect(path string) error {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	m := md5.New()
	m.Write(content)

	hash := hex.EncodeToString(m.Sum(nil))
	c.AddFile(path, hash)

	return nil
}

func (c *Checklist) Diff() (out []string, err error) {
	var content []byte
	for _, file := range c.files {
		content, err = ioutil.ReadFile(file.path)
		if err != nil {
			return nil, err
		}

		m := md5.New()
		m.Write(content)
		if hash := hex.EncodeToString(m.Sum(nil)); hash != file.hash {
			out = append(out, file.path)
		}
	}

	return out, nil
}

func (c *Checklist) Write(w io.Writer) error {
	for _, file := range c.files {
		_, err := io.WriteString(w, fmt.Sprintf("%s %s", file.hash, file.path))
		if err != nil {
			return err
		}
	}

	return nil
}
