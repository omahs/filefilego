package main

import (
	log "github.com/sirupsen/logrus"

	"github.com/peterh/liner"
)

var Stdin = newTerminal()

// Terminal
type Terminal struct {
	*liner.State
	warned     bool
	supported  bool
	normalMode liner.ModeApplier
	rawMode    liner.ModeApplier
}

// GetPassphrase
func (t *Terminal) GetPassphrase(prompt string, confirmation bool) (passwd string, err error) {
	if prompt != "" {
		log.Println(prompt)
	}
	pass, err := t.getPassword("Passphrase:")
	if err != nil {
		log.Fatalf("Error while reading passphrase: %v", err)
	}

	if confirmation {
		confirm, err := t.getPassword("Repeat passphrase: ")
		if err != nil {
			log.Fatalf("Error while reading passphrase confirmation: %v", err)
		}
		if pass != confirm {
			log.Fatalf("Passphrases do not match")
		}
	}
	return pass, nil
}

func (t *Terminal) getPassword(prompt string) (passwd string, err error) {
	if t.supported {
		t.rawMode.ApplyMode()
		defer t.normalMode.ApplyMode()
		return t.State.PasswordPrompt(prompt)
	}
	if !t.warned {
		log.Println("Terminal is unsupported and password will be shown!")
		t.warned = true
	}

	log.Print(prompt)
	passwd, err = t.State.Prompt("")
	log.Println()
	return passwd, err
}

func newTerminal() *Terminal {
	t := new(Terminal)
	normalMode, _ := liner.TerminalMode()
	t.State = liner.NewLiner()
	rawMode, err := liner.TerminalMode()
	if err != nil || !liner.TerminalSupported() {
		t.supported = false
	} else {
		t.supported = true
		t.normalMode = normalMode
		t.rawMode = rawMode
		normalMode.ApplyMode()
	}
	t.SetCtrlCAborts(true)
	t.SetTabCompletionStyle(liner.TabPrints)
	t.SetMultiLineMode(true)
	return t
}
