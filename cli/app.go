package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/urfave/cli"
	"gitlab.com/younixcc/filefilego/common"
	"gitlab.com/younixcc/filefilego/common/hexutil"
	"gitlab.com/younixcc/filefilego/keystore"
	npkg "gitlab.com/younixcc/filefilego/node"
	"gitlab.com/younixcc/filefilego/search"
)

var (
	App = NewApp()
)

func init() {

	App.Action = entry
	App.Version = "0.0.1"
	App.Flags = AppFlags
	sort.Sort(cli.CommandsByName(App.Commands))
	App.Commands = []cli.Command{
		AccountCommand,
	}
	App.After = func(ctx *cli.Context) error {
		return nil
	}
}

func entry(ctx *cli.Context) error {
	cfg := GetConfig(ctx)

	se, err := search.NewSearchEngine(cfg.Global.DataDir + "/" + "searchidx/db.bleve")
	if err != nil {
		log.Fatal("Unable to load or create the search index", err)
	}

	// sitem := search.IndexItem{
	// 	ID:   "idofitem",
	// 	From: "fromme@mdsdsdsda.com",
	// 	Body: "bleve indexing is easy",
	// }

	// se.IndexItem(sitem)
	// res, _ := se.Search("eas")
	se.Search("eas")

	// log.Println(res)

	// return nil

	// check for node identity file first
	key := &keystore.Key{}
	if !common.FileExists(cfg.Global.KeystoreDir + "/node_identity.json") {
		log.Fatal("node identity file doesnt exists. Please run \"filefilego account create_node_key <passphrase>\"")
	} else {

		term := newTerminal()
		pass, err := term.GetPassphrase("Please enter your passphrase to unlock the node identity file", true)
		if err != nil {
			log.Fatal(err)
		}

		bts, err := ioutil.ReadFile(cfg.Global.KeystoreDir + "/node_identity.json")
		if err != nil {
			log.Fatal("Error while reading the node identity file")
		}
		key, err = keystore.UnmarshalKey(bts, pass)
		if err != nil {
			log.Fatal(err)
		}

	}

	ctx2 := context.Background()

	ks := keystore.NewKeyStore(cfg.Global.KeystoreDir)

	listenString := "/ip4/" + cfg.P2P.ListenAddress + "/tcp/" + strconv.Itoa(cfg.P2P.ListenPort)
	node, err := npkg.NewNode(ctx2, listenString, key, ks)
	if err != nil {
		return err
	}

	if cfg.Global.Mine {
		if cfg.Global.MineKeypath == "" {
			log.Fatal("Keyfile can't be empty")
		}
		if !common.FileExists(cfg.Global.MineKeypath) {
			log.Fatal("Couldn't load miner's private key file")
		}
	}

	node.BlockChain = npkg.CreateOrLoadBlockchain(&node, cfg.Global.DataDir, cfg.Global.MineKeypath, cfg.Global.MinePass)

	// register the services
	node.BlockService = npkg.NewBlockService(&node)

	log.Println("Blockchain height: ", node.BlockChain.GetHeight())
	block, _ := node.BlockChain.GetBlockByHeight(node.BlockChain.GetHeight())

	log.Println("Last block ", hexutil.Encode(block.Hash))
	// node.BlockChain.LoadToMemPoolFromDB()

	// apply pubsub gossip to listen for incoming blocks and transactions
	node.ApplyGossip(ctx2)

	hostAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", node.Host.ID().Pretty()))

	for _, lid := range node.Host.Addrs() {
		fulladdr := lid.Encapsulate(hostAddr)
		log.Println("Listening on: ", fulladdr)
	}
	bootnodesCli := cfg.P2P.Bootstraper.Nodes
	if len(bootnodesCli) > 0 {
		err = node.Bootstrap(ctx2, bootnodesCli)
		if err != nil {
			log.Warn("Error while connecting to bootstrap node ", err)
		}
	}

	node.Advertise(ctx2)
	err = node.FindPeers(ctx2)
	if err != nil {
		log.Warn("Unable to find peers", err)
	}

	log.Println("Peerstore count ", node.Peers().Len()-1)

	if cfg.RPC.Enabled {
		if cfg.RPC.HTTP.Enabled {
			go node.StartRPCHTTP(ctx2, cfg.RPC.EnabledServices, cfg.RPC.HTTP.ListenAddress, cfg.RPC.HTTP.ListenPort)
		}
		if cfg.RPC.Websocket.Enabled {
			// node.StartRPCWebSocket()
		}
	}

	log.Println("Syncing node with other peers")
	node.Sync(ctx2)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	err = node.BlockChain.CloseDB()
	if err != nil {
		log.Warn("error while closing the database: ", err)
	}
	if err := node.Host.Close(); err != nil {
		panic(err)
	}
	return nil
}

func main() {
	if err := App.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

}
