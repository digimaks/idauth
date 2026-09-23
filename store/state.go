// SPDX-License-Identifier: EUPL-1.2

package store

import (
	"os"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"github.com/lx-lib/lx-idauth/core"
	"gopkg.in/yaml.v3"
)

type stateStore struct {
	clients map[string]*core.Client
}

func (s stateStore) RefetchClients() error {
	// TODO implement me
	panic("implement me")
}

func (s stateStore) GetClients() []core.Client {
	clients := make([]core.Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, *client)
	}

	return clients
}

func (s stateStore) ValidateCredentials(_ *core.ClientCredentials) error {
	return nil
}

func NewStateStore(app *azugo.App, config *Configuration) (core.ClientStore, error) {
	clients := make([]*core.Client, 0, 1)

	buf, err := os.ReadFile(config.ClientPath)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(buf, &clients)
	if err != nil {
		return nil, err
	}

	clientMap := make(map[string]*core.Client)

	for _, client := range clients {
		err = app.Validate().Struct(client)
		if err != nil {
			return nil, err
		}

		clientMap[client.ID] = client
	}

	return &stateStore{clientMap}, nil
}

func (s stateStore) GetClient(clientID string) (*core.Client, error) {
	client, ok := s.clients[clientID]
	if !ok {
		return nil, http.NotFoundError{Resource: "client"}
	}

	return client, nil
}
