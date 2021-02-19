package search

import (
	"regexp"
	"strings"

	"github.com/blevesearch/bleve"
	"github.com/microcosm-cc/bluemonday"
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

// PrepareIndexingText takes care of inputs with dates and versions and makes them indexable
func PrepareIndexingText(name string) string {
	versionsAndDates := []string{}
	versionRegex := regexp.MustCompile(`(v\d+\.?\d*\.?\d*\.?\d*(\.?\d*)*(.*beta)?(.*alpha)?)`)
	dateRegex := regexp.MustCompile(`(\b(0?[1-9]|[12]\d|30|31)[^\w\d\r\n:](0?[1-9]|1[0-2])[^\w\d\r\n:](\d{4}|\d{2})\b)|(\b(0?[1-9]|1[0-2])[^\w\d\r\n:](0?[1-9]|[12]\d|30|31)[^\w\d\r\n:](\d{4}|\d{2})\b)`)

	foundVersions := versionRegex.FindAllString(name, -1)
	if len(foundVersions) > 0 {
		cleanVer := foundVersions[0]
		if cleanVer[len(cleanVer)-1] == '.' {
			cleanVer = cleanVer[:len(cleanVer)-1]
		}
		versionsAndDates = append(versionsAndDates, cleanVer)
		name = strings.ReplaceAll(name, foundVersions[0], " ")
	}

	foundDates := dateRegex.FindAllString(name, -1)
	if len(foundDates) > 0 {
		cleanDate := foundDates[0]
		if cleanDate[len(cleanDate)-1] == '.' {
			cleanDate = cleanDate[:len(cleanDate)-1]
		}
		versionsAndDates = append(versionsAndDates, cleanDate)
		name = strings.ReplaceAll(name, foundDates[0], " ")
	}

	m := regexp.MustCompile(`[\&\'\"\:\*\?\~]`)
	n := regexp.MustCompile(`[\.\+\-\_\@\{\}\(\)\<\>]`)
	o := regexp.MustCompile(`\s\s+`)

	name = m.ReplaceAllString(name, "")
	name = n.ReplaceAllString(name, " ")
	name += " " + strings.Join(versionsAndDates, " ")
	name = o.ReplaceAllString(name, " ")

	return strings.TrimSpace(name)
}

// IndexItem indexes an item
func (s *SearchEngine) IndexItem(item IndexItem) {
	item.Name = PrepareIndexingText(item.Name)
	p := bluemonday.NewPolicy()
	item.Description = p.Sanitize(item.Description)
	s.Index.Index(item.Hash, item)
}

// Search searches the index
func (s *SearchEngine) Search(searchcString string, searchType int) (*bleve.SearchResult, error) {
	terms := strings.Split(strings.TrimSpace(searchcString), " ")
	cleanTerms := []string{}
	finalTerms := []string{}
	for _, v := range terms {
		if v == "" || v == " " {
			continue
		}
		cleanTerms = append(cleanTerms, strings.TrimSpace(v))
	}

	if len(cleanTerms) > 0 {
		for _, v := range cleanTerms {
			if searchType == 1 {
				// all words required
				v = "+" + v + "*"
			} else if searchType == 2 {
				// any word required
				v = "*" + v + "*"
			}

			finalTerms = append(finalTerms, v)
		}
	}
	searchcString = strings.Join(finalTerms, " ")
	query := bleve.NewQueryStringQuery(searchcString)
	// query := bleve.NewPrefixQuery(searchcString)
	searchRequest := bleve.NewSearchRequest(query)
	searchRequest.Fields = []string{"*"}
	return s.Index.Search(searchRequest)
}
