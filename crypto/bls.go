package crypto

import (
	"errors"

	"github.com/aptos-labs/aptos-go-sdk/bcs"
	"github.com/aptos-labs/aptos-go-sdk/internal/util"
	cosmosbls "github.com/cosmos/crypto/curves/bls12381"
)

const PopLength = 96

type BlsPrivateKey struct {
	Inner cosmosbls.SecretKey // Inner is the actual private key
}

func GenerateBlsPrivateKey() (privateKey *BlsPrivateKey, err error) {
	privKey, err := cosmosbls.RandKey()
	if err != nil {
		return nil, err
	}
	return &BlsPrivateKey{privKey}, nil
}

func (key *BlsPrivateKey) Sign(msg []byte) (authenticator *AccountAuthenticator, err error) {
	signatureBytes := key.Inner.Sign(msg).Marshal()
	var signature BlsSignature
	err = signature.FromBytes(signatureBytes)
	if err != nil {
		return nil, err
	}

	var publicKeyBytes [cosmosbls.PubkeyLength]byte
	copy(publicKeyBytes[:], key.Inner.PublicKey().Marshal())

	return &AccountAuthenticator{
		Variant: AccountAuthenticatorBls,
		Auth: &BlsAuthenticator{
			PubKey: &BlsPublicKey{Inner: publicKeyBytes},
			Sig:    &signature,
		},
	}, nil
}

func (key *BlsPrivateKey) GeneratePubkey() (pk *BlsPublicKey, err error) {
	bz := key.Inner.PublicKey().Marshal()
	err = pk.FromBytes(bz)
	return
}

func (key *BlsPrivateKey) GenerateBlsPop() (*BlsProofOfPossession, error) {
	popBytes := key.Inner.CreatePop().Marshal()
	var pop BlsProofOfPossession
	err := pop.FromBytes(popBytes)
	if err != nil {
		return nil, err
	}
	return &pop, nil
}
func (key *BlsPrivateKey) FromBytes(bytes []byte) (err error) {
	key.Inner, err = cosmosbls.SecretKeyFromBytes(bytes)
	return err
}

type BlsProofOfPossession struct {
	Inner [PopLength]byte
}

func (key *BlsProofOfPossession) MarshalBCS(ser *bcs.Serializer) {
	var pk []byte
	pk = key.Inner[:]
	ser.WriteBytes(pk)
}

func (key *BlsProofOfPossession) UnmarshalBCS(des *bcs.Deserializer) {
	kb := des.ReadBytes()
	if des.Error() != nil {
		return
	}
	err := key.FromBytes(kb)
	if err != nil {
		des.SetError(err)
		return
	}
}

func (key *BlsProofOfPossession) Bytes() []byte {
	return key.Inner[:]
}

func (key *BlsProofOfPossession) FromBytes(bytes []byte) (err error) {
	if len(bytes) != PopLength {
		return errors.New("invalid bls public key size")
	}
	copy(key.Inner[:], bytes)
	return nil
}

func (key *BlsProofOfPossession) FromHex(hexStr string) (err error) {
	bytes, err := util.ParseHex(hexStr)
	if err != nil {
		return err
	}
	return key.FromBytes(bytes)
}

type BlsPublicKey struct {
	Inner [cosmosbls.PubkeyLength]byte // Inner is the actual public key
}

func (key *BlsPublicKey) MarshalBCS(ser *bcs.Serializer) {
	var pk []byte
	pk = key.Inner[:]
	ser.WriteBytes(pk)
}

func (key *BlsPublicKey) UnmarshalBCS(des *bcs.Deserializer) {
	kb := des.ReadBytes()
	if des.Error() != nil {
		return
	}
	err := key.FromBytes(kb)
	if err != nil {
		des.SetError(err)
		return
	}
}

func (key *BlsPublicKey) Verify(msg []byte, sig Signature) bool {
	switch sig := sig.(type) {
	case *BlsSignature:
		var fixedSizeMsg [32]byte
		copy(fixedSizeMsg[:], msg)
		pubKey, err := cosmosbls.PublicKeyFromBytes(key.Bytes())
		if err != nil {
			return false
		}
		valid, _ := cosmosbls.VerifySignature(sig.Bytes(), fixedSizeMsg, pubKey)
		return valid
	default:
		return false
	}
}

func (key *BlsPublicKey) Bytes() []byte {
	return key.Inner[:]
}

func (key *BlsPublicKey) AuthKey() *AuthenticationKey {
	out := &AuthenticationKey{}
	out.FromPublicKey(key)
	return out
}

func (key *BlsPublicKey) ToHex() string {
	return util.BytesToHex(key.Bytes())
}

func (key *BlsPublicKey) FromBytes(bytes []byte) (err error) {
	if len(bytes) != cosmosbls.PubkeyLength {
		return errors.New("invalid bls public key size")
	}
	copy(key.Inner[:], bytes)
	return nil
}

func (key *BlsPublicKey) FromHex(hexStr string) (err error) {
	bytes, err := util.ParseHex(hexStr)
	if err != nil {
		return err
	}
	return key.FromBytes(bytes)
}

func (key *BlsPublicKey) Scheme() uint8 {
	return BlsKeyScheme
}

type BlsSignature struct {
	Inner [cosmosbls.SignatureLength]byte // Inner is the actual private key
}

func (b *BlsSignature) Bytes() []byte {
	return b.Inner[:]
}

func (b *BlsSignature) FromBytes(bytes []byte) (err error) {
	if len(bytes) != cosmosbls.SignatureLength {
		return errors.New("invalid bls signature size")
	}
	copy(b.Inner[:], bytes)
	return nil
}

func (b *BlsSignature) ToHex() string {
	return util.BytesToHex(b.Bytes())
}

func (b *BlsSignature) FromHex(hexStr string) (err error) {
	bytes, err := util.ParseHex(hexStr)
	if err != nil {
		return err
	}
	return b.FromBytes(bytes)
}

func (b *BlsSignature) MarshalBCS(ser *bcs.Serializer) {
	ser.WriteBytes(b.Bytes())
}

func (b *BlsSignature) UnmarshalBCS(des *bcs.Deserializer) {
	bytes := des.ReadBytes()
	if des.Error() != nil {
		return
	}
	err := b.FromBytes(bytes)
	if err != nil {
		des.SetError(err)
	}
}

type BlsAuthenticator struct {
	PubKey *BlsPublicKey // PubKey is the public key
	Sig    *BlsSignature // Sig is the signature
}

func (ba *BlsAuthenticator) MarshalBCS(ser *bcs.Serializer) {
	ser.Struct(ba.PublicKey())
	ser.Struct(ba.Signature())
}

func (ba *BlsAuthenticator) UnmarshalBCS(des *bcs.Deserializer) {
	ba.PubKey = &BlsPublicKey{}
	des.Struct(ba.PubKey)
	if des.Error() != nil {
		return
	}
	ba.Sig = &BlsSignature{}
	des.Struct(ba.Sig)
}

func (ba *BlsAuthenticator) PublicKey() PublicKey {
	return ba.PubKey
}

func (ba *BlsAuthenticator) Signature() Signature {
	return ba.Sig
}

func (ba *BlsAuthenticator) Verify(msg []byte) bool {
	return ba.PubKey.Verify(msg, ba.Sig)
}
