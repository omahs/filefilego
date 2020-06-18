package node

import (
	"context"
)

// FilefilegoAPI
type FilefilegoAPI struct {
	Node *Node
}

// NewFilefilegoAPI
func NewFilefilegoAPI(node *Node) *FilefilegoAPI {
	return &FilefilegoAPI{Node: node}
}

// FilefilegoResult ...
type FilefilegoResult struct {
	IsSyncing    bool   `json:"is_syncing"`
	HighestBlock uint64 `json:"highest_block"`
	CurrentBlock uint64 `json:"current_block"`
}

// Syncing checks if client is syncing
func (api *FilefilegoAPI) Syncing(ctx context.Context) (FilefilegoResult, error) {
	dt := FilefilegoResult{
		IsSyncing:    api.Node.IsSyncing(),
		HighestBlock: api.Node.BlockService.GetHeighestBlock(),
		CurrentBlock: api.Node.BlockChain.GetHeight(),
	}
	return dt, nil
}

// BlockchainHeight
func (api *FilefilegoAPI) BlockchainHeight(ctx context.Context) (uint64, error) {
	return api.Node.BlockChain.GetHeight(), nil
}

// PeerCount
func (api *FilefilegoAPI) PeerCount(ctx context.Context) (int, error) {
	return api.Node.Peers().Len(), nil
}

// Verifier
func (api *FilefilegoAPI) Verifier(ctx context.Context) (string, error) {
	return GetBlockchainSettings().Verifiers[0].Address, nil
}
