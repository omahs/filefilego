package node

import (
	"github.com/filefilego/filefilego/common/hexutil"
)

// BlockchainSettings represents starting point of the blockchain
type BlockchainSettings struct {
	BlockchainVersion        string     `json:"blockchain_version"`
	Chain                    []byte     `json:"chain"`
	GenesisHash              string     `json:"genesis_hash"`
	BlockTimeSeconds         int        `json:"block_time_seconds"`
	InitialBlockReward       string     `json:"initial_block_reward"`
	MaxSupply                string     `json:"max_supply"`
	DropRewardDays           int        `json:"drop_reward_days"`
	DropRewardFactor         int        `json:"drop_reward_factor"`
	NamespaceEnabled         bool       `json:"namespace_enabled"`
	NamespaceRegistrationFee string     `json:"namespace_registration_fee"`
	NodeCreationFeesGuest    string     `json:"node_creation_fees_guest"`
	Verifiers                []Verifier `json:"verifiers"`
}

// GetBlockchainSettings returns the genesis data
func GetBlockchainSettings() BlockchainSettings {
	gen := BlockchainSettings{
		BlockchainVersion:  "0.5.1",
		Chain:              hexutil.MustDecode("0x01"), // 1 for Mainnet, anything else for other chains
		GenesisHash:        "c2005c6ea44df4800bbd56d857bb6cb727acde486869553d212056bea38438e9",
		BlockTimeSeconds:   10,
		InitialBlockReward: "15000000000000000000",        // 15 zarans
		MaxSupply:          "500000000000000000000000000", // 500M zarans
		DropRewardDays:     1095,                          //3 years
		DropRewardFactor:   2,
		NamespaceEnabled:   true,
		//NamespaceRegistrationFee: "10000000000000000000000", //10k zarans
		NamespaceRegistrationFee: "15000000000000000000", //15 zarans
		NodeCreationFeesGuest:    "1000000000000000000",  //1 Zaran
		Verifiers: []Verifier{
			{
				Address:        "0xcfc954667d85b9ff0a29093df130b1249bb743f1",
				InitialBalance: "0",
				PublicKey:      "0x0327ee3ce92a07f46a47c2ebfe960444af034c6066bbb68488bce64e29f6c0c03e",
			},
		},
	}
	return gen
}
