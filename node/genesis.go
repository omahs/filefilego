package node

type BlockchainSettings struct {
	BlockTimeSeconds         int
	InitialBlockReward       string
	MaxSupply                string
	DropRewardDays           int
	DropRewardFactor         int
	NamespaceEnabled         bool
	NamespaceRegistrationFee string
	Verifiers                []Verifier
}

// GetBlockchainSettings returns the genesis data
func GetBlockchainSettings() BlockchainSettings {
	gen := BlockchainSettings{
		BlockTimeSeconds:         10,
		InitialBlockReward:       "15000000000000000000",        // 15 zarans
		MaxSupply:                "500000000000000000000000000", // 500M zarans
		DropRewardDays:           1095,                          //3 years
		DropRewardFactor:         2,
		NamespaceEnabled:         true,
		NamespaceRegistrationFee: "10000000000000000000000", //10k zarans
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
