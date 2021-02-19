package node

import (
	"bytes"
	"context"
	"errors"

	"github.com/boltdb/bolt"
	"github.com/golang/protobuf/proto"
)

// ChannelAPI represents rpc methods for the channel functionality
type ChannelAPI struct {
	Node *Node
}

// NewChannelAPI creates a new chanai
func NewChannelAPI(node *Node) *ChannelAPI {
	return &ChannelAPI{Node: node}
}

// ChanNodeListJSONResponse is used to represent a list of channels and pagination params
type ChanNodeListJSONResponse struct {
	Total    int        `json:"total"`
	Limit    int        `json:"limit"`
	Offset   int        `json:"offset"`
	Channels []ChanNode `json:"channels"`
}

// List all channels
func (api *ChannelAPI) List(ctx context.Context, limit int, offset int) (ChanNodeListJSONResponse, error) {
	db := api.Node.BlockChain.db
	pl := ChanNodeListJSONResponse{Limit: limit, Offset: offset}

	if err := db.View(func(tx *bolt.Tx) error {
		// Assume bucket exists and has keys
		b := tx.Bucket([]byte(channelBucket))
		nbucket := tx.Bucket([]byte(nodesBucket))
		pl.Total = b.Stats().KeyN
		c := b.Cursor()
		index := 0
		accepted := 0
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			index++
			if limit == accepted {
				break
			}
			if index < offset+1 {
				continue
			}

			v := nbucket.Get(k)
			channel := ChanNode{}
			proto.Unmarshal(v, &channel)
			pl.Channels = append(pl.Channels, channel)
			accepted++
		}
		return nil
	}); err != nil {
		return pl, err
	}
	if limit > pl.Total {
		pl.Limit = pl.Total
	}

	return pl, nil
}

// ChanNodeJSONResponse is used to represent a node with its childs and parent
type ChanNodeJSONResponse struct {
	Node   ChanNode   `json:"node"`
	Parent ChanNode   `json:"parent"`
	Childs []ChanNode `json:"childs"`
}

// GetNode gets a node given its hash
func (api *ChannelAPI) GetNode(ctx context.Context, hash string) (response ChanNodeJSONResponse, err error) {
	db := api.Node.BlockChain.db
	if err := db.View(func(tx *bolt.Tx) error {

		b := tx.Bucket([]byte(nodesBucket))
		v := b.Get([]byte(hash))
		if v == nil {
			return errors.New("Node not found with given hash")
		}

		err := proto.Unmarshal(v, &response.Node)
		if err != nil {
			return err
		}

		// get parrent if not is not a channel
		if response.Node.NodeType != ChanNodeType_CHANNEL {
			v := b.Get([]byte(response.Node.ParentHash))
			if v == nil {
				return errors.New("Node not found with given hash")
			}
			err := proto.Unmarshal(v, &response.Parent)
			if err != nil {
				return err
			}
		}

		// get its childs
		c := tx.Bucket([]byte(nodeNodesBucket)).Cursor()
		prefix := []byte(hash)
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			// fmt.Printf("key=%s, value=%s\n", k, v)
			val := b.Get(v)
			if val == nil {
				continue
			}

			tmpNode := ChanNode{}
			err := proto.Unmarshal(val, &tmpNode)
			if err != nil {
				return err
			}
			response.Childs = append(response.Childs, tmpNode)
		}

		return nil
	}); err != nil {

		return response, err
	}
	return response, nil
}

// Search uses fulltext search for name and description
func (api *ChannelAPI) Search(ctx context.Context, query string, limit int) (response []ChanNode, err error) {
	if limit > api.Node.SearchEngine.MaxSearchDocumentsPerQuery {
		limit = api.Node.SearchEngine.MaxSearchDocumentsPerQuery
	}
	res, err := api.Node.SearchEngine.Search(query)
	if err != nil {
		return response, err
	}

	fetchs := 0
	err = api.Node.BlockChain.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(nodesBucket))
		for _, v := range res.Hits {
			if limit == fetchs {
				break
			}

			hash := v.Fields["Hash"].(string)
			// nodeType := v.Fields["Type"].(int32)
			v := b.Get([]byte(hash))
			if v == nil {
				continue
			}

			tmpNode := ChanNode{}
			err := proto.Unmarshal(v, &tmpNode)
			if err != nil {
				continue
			}

			response = append(response, tmpNode)
			fetchs++
		}

		return nil
	})

	if err != nil {
		return response, err

	}

	return response, nil
}
