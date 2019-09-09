package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	root = &cobra.Command{
		Use:   "journal",
		Short: "journal is an encryption helper for text files",
		Run:   func(cmd *cobra.Command, args []string) {},
	}
	unlock = &cobra.Command{
		Use:   "unlock [dir]",
		Short: "Open a directory of encrypted text files",
		Run: func(cmd *cobra.Command, args []string) {
			journal, err := NewJournalFromArgs(args)
			if err != nil {
				log.Fatal(err)
			}

			err = journal.Unlock()
			if err != nil {
				log.Fatal(err)
			}
		},
	}

	nonHiddenFilesFilter = func(path string, _ os.FileInfo) bool {
		return strings.HasPrefix(filepath.Base(path), ".")
	}
)

func init() {
	root.AddCommand(unlock)
}

func main() {
	if err := root.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var DefaultFileExt = ".gpg"

type Journal struct {
	RootDir string
	Files   []FilePair

	encryptedFileExt string
	gpgCommand       string
	gpgReceiver      string
}

func NewJournalFromArgs(args []string) (*Journal, error) {
	var (
		err error
	)

	journal := &Journal{
		encryptedFileExt: DefaultFileExt,
		gpgCommand:       "gpg",
	}

	if len(args) == 0 {
		journal.RootDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("Error determining current directory: %s", err)
		}
	} else {
		journal.RootDir, err = filepath.Abs(args[0])
		if err != nil {
			return nil, fmt.Errorf("Error: %s is not a valid path: %s", args[0], err)
		}
	}

	gpgid, err := ioutil.ReadFile(path.Join(journal.RootDir, ".gpgid"))
	if err != nil && os.IsNotExist(err) {
		fmt.Println("Journal directory is not initialised. Run journal init.")
		os.Exit(0)
	}
	journal.gpgReceiver = strings.TrimSpace(string(gpgid))

	err = filepath.Walk(journal.RootDir, journal.walkFile)
	if err != nil {
		return nil, err
	}

	return journal, nil
}

func (j *Journal) Unlock() error {
	for _, f := range j.Files {
		if err := f.Decrypt(j); err != nil {
			return fmt.Errrof("Error decrypting file %s: %s", f.enc, err)
		}

		if err := f.LeaveFootprint(); err != nil {
			return fmt.Errorf("Error creating file footprint %s: %s", f.enc, err)
		}
	}

	checklist, err := ChecklistFromDir(j.RootDir, nonHiddenFilesFilter)
	if err != nil {
		return fmt.Errorf("Error reading checklist from dir: %s", err)
	}

	checkfile, err := os.Create(path.Join(j.RootDir, ".check"))
	if err != nil {
		return fmt.Errorf("Error creating checklist file: %s", err)
	}

	checkWriter := bufio.NewWriter(checkfile)
	if err := checklist.Write(checkWriter); err != nil {
		return fmt.Errorf("Error writing checklist file: %s", err)
	}
	checkWriter.Flush()
	checkfile.Close()

	return nil
}

func (j *Journal) Lock() error {
	checkfile, err := os.Open(path.Join(j.RootDir, ".check"))
	if err != nil {
		return fmt.Errorf("Could not find open checklist file: %s", err)
	}
	defer checkfile.Close()

	checklist, err := ChecklistFromReader(bufio.NewReader(checkfile))
	if err != nil {
		return fmt.Errorf("Could not read from checklist file: %s", err)
	}

	// calculate which files have changed
	changes, err := checklist.Diff()
	if err != nil {
		return fmt.Errorf("Could not calculate file changes: %s", err)
	}
	hasChanged := func(path string) bool {
		for _, changed := changes {
			if path == changed {
				return true
			}
		}

		return false
	}

	// reset or re-rencrypt files
	for _, file := j.Files {
		if !hasChanged(file) {
			file.Reset()
			continue
		}

		if err := file.Encrypt(j); err != nil {
			return err
		}

		if err := file.RemoveFootprint(); err != nil {
			return err
		}
	}

	return nil
}

func (j *Journal) Status() error {
	return nil
}

func (j *Journal) walkFile(path string, info os.FileInfo, err error) error {
	if err != nil {
		log.Fatal(err)
	}

	if filepath.Ext(path) != j.encryptedFileExt {
		return nil
	}

	hidden := strings.HasPrefix(filepath.Base(path), ".")
	raw := path.Join(
		filepath.Dir(path),
		strings.TrimPrefix(".", filepath.Base(path)),
	)

	file := FilePair{
		enc:    path,
		plain:  strings.TrimSuffix(path, j.encryptedFileExt),
		hidden: hidden,
	}

	j.Files = append(j.Files, file)
	return nil
}

type FilePair struct {
	enc    string
	plain  string
	hidden bool
}

func (fp FilePair) Decrypt(j *Journal) error {
	args := []string{
		"-d",
		"--batch", // non-interactive
		"--yes",   // assume yes to most questions
		fmt.Sprintf(`-r"%s"`, j.gpgReceiver),
		fmt.Sprintf("-o%s", fp.plain),
		fp.enc,
	}

	fmt.Printf("Executing %s %s\n", j.gpgCommand, strings.Join(args, " "))

	cmd := exec.Command(j.gpgCommand, args...)
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func (fp FilePair) Encrypt(j *Journal) error {
	args := []string{
		"-e",
		"--batch", // non-interactive
		"--yes",   // assume yes to most questions
		fmt.Sprintf("-o%s", fp.enc),
		fmt.Sprintf(`-r"%s"`, j.gpgReceiver),
		fp.plain,
	}

	fmt.Printf("Executing %s %s\n", j.gpgCommand, strings.Join(args, " "))

	cmd := exec.Command(j.gpgCommand, args...)
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func (fp FilePair) LeaveFootprint() error {
	dirname := filepath.Dir(fp.enc)
	basename := filepath.Base(fp.enc)
	return exec.Command("mv", fp.enc, path.Join(dirname, "."+basename)).Run()
}

func (fp FilePair) RemoveFootprint() error {
	dirname := filepath.Dir(fp.enc)
	basename := filepath.Base(fp.enc)
	return exec.Command("rm", path.Join(dirname, "."+basename)).Run()
}

func (fp FilePair) Reset() error {
	dirname := filepath.Dir(fp.enc)
	basename := filepath.Base(fp.enc)

	return exec.Command("mv", path.Join(dirname, "."+basename), fp.enc).Run()
}
