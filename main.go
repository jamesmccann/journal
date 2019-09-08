package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"

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

			journal.Unlock()
		},
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
		gpgReceiver:      "",
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

	err = filepath.Walk(journal.RootDir, journal.walkFile)
	if err != nil {
		return nil, err
	}

	return journal, nil
}

func (j *Journal) Unlock() error {
	var (
		decryptCh = make(chan FilePair, 10)
		hashCh    = make(chan FilePair, 10)
		chksumCh  = make(chan FilePair, 100)
	)

	wg := &sync.WaitGroup{}

	// decrypt
	go func() {
		for fp := range decryptCh {
			log.Printf("Decrypting %s", fp.enc)
			if err := fp.Decrypt(j); err != nil {
				fmt.Printf("Error decrypting file %s: %s", fp.enc, err)
				os.Exit(1)
			}
			hashCh <- fp
		}
	}()

	// hash
	go func() {
		for fp := range hashCh {
			log.Printf("Hashing %s", fp.plain)
			if err := fp.CalculateHash(j); err != nil {
				fmt.Printf("Error calculating file hash %s: %s", fp.enc, err)
				os.Exit(1)
			}
			chksumCh <- fp
		}
	}()

	chkFile, err := os.Create(path.Join(j.RootDir, ".check"))
	if err != nil {
		fmt.Printf("Error opening checksum file for writing: %s", err)
		os.Exit(1)
	}
	chkWriter := bufio.NewWriter(chkFile)

	// write checksums
	go func() {
		for fp := range chksumCh {
			chkWriter.Write(fp.plainHash)
			wg.Done()
		}
	}()

	// enqueue
	wg.Add(len(j.Files))
	for _, file := range j.Files {
		decryptCh <- file
	}

	wg.Wait()
	chkWriter.Flush()
	chkFile.Close()

	return nil
}

func (j *Journal) Lock() error {

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

	fp := NewFilePair(path, strings.TrimSuffix(path, j.encryptedFileExt))

	j.Files = append(j.Files, fp)
	return nil
}

type FilePair struct {
	enc       string
	plain     string
	plainHash []byte
}

func NewFilePair(enc string, plain string) FilePair {
	return FilePair{
		enc:   enc,
		plain: plain,
	}
}

func (fp *FilePair) Decrypt(j *Journal) error {
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

func (fp *FilePair) CalculateHash(j *Journal) error {
	// create an md5 checklist for the decrypted files
	args := []string{
		"-r",
		fp.plain,
	}

	// TODO: read file and use go md5
	out, err := exec.Command("md5", args...).Output()
	if err != nil {
		return err
	}
	fp.plainHash = out

	return nil
}

func (fp *FilePair) Encrypt(j *Journal) error {
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
