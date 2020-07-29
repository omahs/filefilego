package rpc

import (
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/ethereum/go-ethereum/rpc"
)

// ServeHTTP registers all the required namespaces
func ServeHTTP(apis []API) http.HandlerFunc {
	server := rpc.NewServer()
	for _, api := range apis {
		if api.Enabled {
			err := server.RegisterName(api.Namespace, api.Service)
			if err != nil {
				log.Fatal("Unable to register the jsonrpc namespace")
			}
		}
	}
	return globalMidware(apis, server)
}

// globalMidware acts as a global middleware
func globalMidware(apis []API, next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	}
}
