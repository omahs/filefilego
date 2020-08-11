package main

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli"
	"github.com/filefilego/filefilego/keystore"
)

var (
	// AccountCommand
	AccountCommand = cli.Command{
		Name:     "account",
		Usage:    "Manage accounts",
		Category: "Account",
		Description: `
					Manage accounts, create, delete load etc.`,
		Subcommands: []cli.Command{
			{
				Name:   "create",
				Usage:  "create <passphrase>",
				Action: CreateAccount,
				Flags:  []cli.Flag{},
				Description: `
				Creates a new account from passphrase`,
			},
			{
				Name:   "create_node_key",
				Usage:  "create_node_key <passphrase>",
				Action: CreateNodeKeys,
				Flags:  []cli.Flag{},
				Description: `
				Creates a a node key`,
			},
			{
				Name:   "list",
				Usage:  "list",
				Action: ListAccounts,
				Flags:  []cli.Flag{},
				Description: `
				lists all available accounts`,
			},
		},
	}
)

// ListAccounts
func ListAccounts(ctx *cli.Context) error {
	cfg := GetConfig(ctx)

	ks := keystore.NewKeyStore(cfg.Global.KeystoreDir)

	files := ks.ListAccounts()
	for _, file := range files {
		log.Println(file)
	}
	return nil
}

// CreateAccount
func CreateAccount(ctx *cli.Context) error {
	cfg := GetConfig(ctx)

	ks := keystore.NewKeyStore(cfg.Global.KeystoreDir)
	if len(ctx.Args()) == 0 {
		log.Fatal("Passphrase is required")
	}
	ks.NewAccount(ctx.Args()[0])
	return nil
}

// CreateNodeKeys
func CreateNodeKeys(ctx *cli.Context) error {
	cfg := GetConfig(ctx)

	ks := keystore.NewKeyStore(cfg.Global.KeystoreDir)
	if len(ctx.Args()) == 0 {
		log.Fatal("Passphrase is required")
	}
	filename := ks.NewAccount(ctx.Args()[0])
	finalDestination := "node_identity.json"
	err := os.Rename(filename, cfg.Global.KeystoreDir+"/"+finalDestination)
	if err != nil {
		log.Fatal("Unable to create a new node identity")
	}
	log.Println("Your node identity is located at: ", cfg.Global.KeystoreDir+"/"+finalDestination)
	return nil
}
