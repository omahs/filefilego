package search

import (
	"github.com/blevesearch/bleve"
)

type SearchEngine struct {
	Enabled                    bool
	DBPath                     string
	Index                      bleve.Index
	MaxSearchDocumentsPerQuery int
}

type IndexItem struct {
	Hash        string
	Type        int32
	Name        string
	Description string
}

func NewSearchEngine(dbPath string, max int) (s SearchEngine, err error) {
	mapping := bleve.NewIndexMapping()
	var index bleve.Index

	index, err = bleve.New(dbPath, mapping)
	if err != nil {
		index, err = bleve.Open(dbPath)
	}

	if err != nil {
		return s, err
	}

	s.Index = index
	s.DBPath = dbPath
	s.MaxSearchDocumentsPerQuery = max

	return s, nil
}

// IndexItem indexes an item
func (s *SearchEngine) IndexItem(item IndexItem) {
	s.Index.Index(item.Hash, item)
}

// Search searchs the index
func (s *SearchEngine) Search(searchcString string) (*bleve.SearchResult, error) {
	query := bleve.NewQueryStringQuery(searchcString)
	// query := bleve.NewPrefixQuery(searchcString)
	searchRequest := bleve.NewSearchRequest(query)
	searchRequest.Fields = []string{"*"}
	return s.Index.Search(searchRequest)
}
