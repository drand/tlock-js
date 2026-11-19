package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"filippo.io/age/armor"
	"github.com/drand/drand/v2/crypto"
	"github.com/drand/kyber"
	"github.com/drand/tlock"
)

type vector struct {
	Chain struct {
		Hash      string
		PublicKey string
		Scheme    string
	}
	Beacon struct {
		Round     uint64
		Signature string
	}
}

type offlineNetwork struct {
	hash      string
	scheme    crypto.Scheme
	key       kyber.Point
	round     uint64
	signature []byte
}

func (n offlineNetwork) ChainHash() string        { return n.hash }
func (n offlineNetwork) Current(time.Time) uint64 { return n.round }
func (n offlineNetwork) PublicKey() kyber.Point   { return n.key }
func (n offlineNetwork) Scheme() crypto.Scheme    { return n.scheme }
func (n offlineNetwork) SwitchChainHash(string) error {
	return errors.New("chain hash is pinned")
}

func (n offlineNetwork) Signature(round uint64) ([]byte, error) {
	if round != n.round {
		return nil, errors.New("unexpected round")
	}
	return n.signature, nil
}

func run(operation string, input string) error {
	var fixture vector
	if err := json.Unmarshal([]byte(input), &fixture); err != nil {
		return err
	}
	scheme, err := crypto.SchemeFromName(fixture.Chain.Scheme)
	if err != nil {
		return err
	}
	keyBytes, err := hex.DecodeString(fixture.Chain.PublicKey)
	if err != nil {
		return err
	}
	key := scheme.KeyGroup.Point()
	if err := key.UnmarshalBinary(keyBytes); err != nil {
		return err
	}
	signature, err := hex.DecodeString(fixture.Beacon.Signature)
	if err != nil {
		return err
	}
	engine := tlock.New(offlineNetwork{fixture.Chain.Hash, *scheme, key, fixture.Beacon.Round, signature}).Strict()
	switch operation {
	case "encrypt":
		return engine.Encrypt(os.Stdout, os.Stdin, fixture.Beacon.Round)
	case "armor":
		writer := armor.NewWriter(os.Stdout)
		if err := engine.Encrypt(writer, os.Stdin, fixture.Beacon.Round); err != nil {
			return err
		}
		return writer.Close()
	case "decrypt":
		return engine.Decrypt(os.Stdout, os.Stdin)
	default:
		return errors.New("unknown operation")
	}
}

func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
