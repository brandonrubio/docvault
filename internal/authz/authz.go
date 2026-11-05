// Package authz wraps the OpenFGA Go SDK behind a small interface so the HTTP
// layer never deals with SDK types and can be tested with a fake.
package authz

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"

	openfga "github.com/openfga/go-sdk"
	"github.com/openfga/go-sdk/client"
	"github.com/openfga/language/pkg/go/transformer"
)

// ModelDSL is the authorization model in the OpenFGA DSL.
//
//go:embed model.fga
var ModelDSL string

// Tuple is a relationship tuple: "User has Relation on Object".
type Tuple struct {
	User     string
	Relation string
	Object   string
}

// Authorizer is the set of authorization operations the application needs.
type Authorizer interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error)
	// Write adds tuples, silently skipping ones that already exist.
	Write(ctx context.Context, tuples ...Tuple) error
	// Delete removes tuples, silently skipping ones that do not exist.
	Delete(ctx context.Context, tuples ...Tuple) error
	// DeleteObject removes every tuple whose object is the given one (all shares,
	// ownership and parent links), so nothing can outlive the resource.
	DeleteObject(ctx context.Context, object string) error
	// Exists reports whether any tuple with this relation exists on the object.
	Exists(ctx context.Context, object, relation string) (bool, error)
}

// Config configures the OpenFGA connection.
type Config struct {
	APIURL    string // e.g. http://localhost:8080
	StoreID   string // optional: reuse an existing store
	StoreName string // used when a new store has to be created
}

// Client is the OpenFGA-backed Authorizer.
type Client struct {
	fga     *client.OpenFgaClient
	StoreID string
	ModelID string
}

var _ Authorizer = (*Client)(nil)

// New connects to OpenFGA, creating a store if cfg.StoreID is empty, and
// publishes the embedded authorization model to it.
func New(ctx context.Context, cfg Config) (*Client, error) {
	fga, err := client.NewSdkClient(&client.ClientConfiguration{
		ApiUrl:  cfg.APIURL,
		StoreId: cfg.StoreID,
	})
	if err != nil {
		return nil, fmt.Errorf("create openfga client: %w", err)
	}

	storeID := cfg.StoreID
	if storeID == "" {
		name := cfg.StoreName
		if name == "" {
			name = "docvault"
		}
		// Reuse a store with this name if one exists, so restarts keep their data.
		list, err := fga.ListStores(ctx).Execute()
		if err != nil {
			return nil, fmt.Errorf("list stores: %w", err)
		}
		for _, st := range list.GetStores() {
			if st.GetName() == name {
				storeID = st.GetId()
				break
			}
		}
		if storeID == "" {
			resp, err := fga.CreateStore(ctx).Body(client.ClientCreateStoreRequest{Name: name}).Execute()
			if err != nil {
				return nil, fmt.Errorf("create store: %w", err)
			}
			storeID = resp.GetId()
		}
		if err := fga.SetStoreId(storeID); err != nil {
			return nil, err
		}
	}

	modelID, err := writeModel(ctx, fga)
	if err != nil {
		return nil, err
	}
	if err := fga.SetAuthorizationModelId(modelID); err != nil {
		return nil, err
	}
	return &Client{fga: fga, StoreID: storeID, ModelID: modelID}, nil
}

// writeModel converts the DSL to the JSON API representation and uploads it.
func writeModel(ctx context.Context, fga *client.OpenFgaClient) (string, error) {
	modelJSON, err := transformer.TransformDSLToJSON(ModelDSL)
	if err != nil {
		return "", fmt.Errorf("parse model DSL: %w", err)
	}
	var body openfga.WriteAuthorizationModelRequest
	if err := json.Unmarshal([]byte(modelJSON), &body); err != nil {
		return "", fmt.Errorf("decode model JSON: %w", err)
	}
	resp, err := fga.WriteAuthorizationModel(ctx).Body(body).Execute()
	if err != nil {
		return "", fmt.Errorf("write authorization model: %w", err)
	}
	return resp.GetAuthorizationModelId(), nil
}

func (c *Client) Check(ctx context.Context, user, relation, object string) (bool, error) {
	resp, err := c.fga.Check(ctx).Body(client.ClientCheckRequest{
		User:     user,
		Relation: relation,
		Object:   object,
	}).Execute()
	if err != nil {
		return false, fmt.Errorf("check %s %s %s: %w", user, relation, object, err)
	}
	return resp.GetAllowed(), nil
}

func (c *Client) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	resp, err := c.fga.ListObjects(ctx).Body(client.ClientListObjectsRequest{
		User:     user,
		Relation: relation,
		Type:     objectType,
	}).Execute()
	if err != nil {
		return nil, fmt.Errorf("list objects: %w", err)
	}
	return resp.GetObjects(), nil
}

func (c *Client) Write(ctx context.Context, tuples ...Tuple) error {
	var keys []client.ClientTupleKey
	for _, t := range tuples {
		ok, err := c.hasTuple(ctx, t)
		if err != nil {
			return err
		}
		if !ok {
			keys = append(keys, client.ClientTupleKey{User: t.User, Relation: t.Relation, Object: t.Object})
		}
	}
	if len(keys) == 0 {
		return nil
	}
	if _, err := c.fga.Write(ctx).Body(client.ClientWriteRequest{Writes: keys}).Execute(); err != nil {
		return fmt.Errorf("write tuples: %w", err)
	}
	return nil
}

func (c *Client) Delete(ctx context.Context, tuples ...Tuple) error {
	var keys []client.ClientTupleKeyWithoutCondition
	for _, t := range tuples {
		ok, err := c.hasTuple(ctx, t)
		if err != nil {
			return err
		}
		if ok {
			keys = append(keys, client.ClientTupleKeyWithoutCondition{User: t.User, Relation: t.Relation, Object: t.Object})
		}
	}
	if len(keys) == 0 {
		return nil
	}
	if _, err := c.fga.Write(ctx).Body(client.ClientWriteRequest{Deletes: keys}).Execute(); err != nil {
		return fmt.Errorf("delete tuples: %w", err)
	}
	return nil
}

func (c *Client) Exists(ctx context.Context, object, relation string) (bool, error) {
	resp, err := c.fga.Read(ctx).Body(client.ClientReadRequest{
		Object:   &object,
		Relation: &relation,
	}).Execute()
	if err != nil {
		return false, fmt.Errorf("read tuples: %w", err)
	}
	return len(resp.GetTuples()) > 0, nil
}

func (c *Client) hasTuple(ctx context.Context, t Tuple) (bool, error) {
	resp, err := c.fga.Read(ctx).Body(client.ClientReadRequest{
		User:     &t.User,
		Relation: &t.Relation,
		Object:   &t.Object,
	}).Execute()
	if err != nil {
		return false, fmt.Errorf("read tuple: %w", err)
	}
	return len(resp.GetTuples()) > 0, nil
}

func (c *Client) DeleteObject(ctx context.Context, object string) error {
	for i := 0; i < 1000; i++ { // bounded: each pass deletes at least one page
		resp, err := c.fga.Read(ctx).Body(client.ClientReadRequest{Object: &object}).Execute()
		if err != nil {
			return fmt.Errorf("read tuples: %w", err)
		}
		tuples := resp.GetTuples()
		if len(tuples) == 0 {
			return nil
		}
		keys := make([]client.ClientTupleKeyWithoutCondition, 0, len(tuples))
		for _, t := range tuples {
			k := t.GetKey()
			keys = append(keys, client.ClientTupleKeyWithoutCondition{User: k.GetUser(), Relation: k.GetRelation(), Object: k.GetObject()})
		}
		for len(keys) > 0 { // the write API accepts at most 100 changes
			n := min(len(keys), 100)
			if _, err := c.fga.Write(ctx).Body(client.ClientWriteRequest{Deletes: keys[:n]}).Execute(); err != nil {
				return fmt.Errorf("delete tuples: %w", err)
			}
			keys = keys[n:]
		}
	}
	return fmt.Errorf("delete tuples on %s: too many pages", object)
}
