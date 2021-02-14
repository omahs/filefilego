package node

import (
	"context"
)

// ChannelAPI represents rpc methods for the channel functionality
type ChannelAPI struct {
	Node *Node
}

// NewChannelAPI creates a new chanai
func NewChannelAPI(node *Node) *ChannelAPI {
	return &ChannelAPI{Node: node}
}

// Register a channel
func (api *ChannelAPI) Register(ctx context.Context, accessToken string, address string) (string, error) {
	return "{{channel_hash}}", nil
}
