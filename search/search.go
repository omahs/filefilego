package search

import (
	"github.com/blevesearch/bleve"
)

type SearchEngine struct {
	DBPath string
	Index  bleve.Index
}

type IndexItem struct {
	ID   string
	From string
	Body string
}

func NewSearchEngine(dbPath string) (s SearchEngine, err error) {
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

	return s, nil
}

// IndexItem indexes an item
func (s *SearchEngine) IndexItem(item IndexItem) {
	s.Index.Index(item.ID, item)
}

// Search searchs the index
func (s *SearchEngine) Search(searchcString string) (*bleve.SearchResult, error) {
	// query := bleve.NewQueryStringQuery(searchcString)
	query := bleve.NewPrefixQuery(searchcString)
	searchRequest := bleve.NewSearchRequest(query)
	return s.Index.Search(searchRequest)
}
