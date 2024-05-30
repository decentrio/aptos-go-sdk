package api

import (
	"encoding/json"
	"fmt"
	"github.com/aptos-labs/aptos-go-sdk/internal/types"
)

const (
	EnumPendingTransaction         = "pending_transaction"
	EnumUserTransaction            = "user_transaction"
	EnumGenesisTransaction         = "genesis_transaction"
	EnumBlockMetadataTransaction   = "block_metadata_transaction"
	EnumStateCheckpointTransaction = "state_checkpoint_transaction"
	EnumValidatorTransaction       = "validator_transaction"
)

// Transaction is an enum type for all possible transactions on the blockchain
type Transaction struct {
	Type  string
	Inner TransactionImpl
}

func (o *Transaction) UnmarshalJSON(b []byte) error {
	type inner struct {
		Type string `json:"type"`
	}
	data := &inner{}
	err := json.Unmarshal(b, &data)
	if err != nil {
		return err
	}
	o.Type = data.Type
	switch o.Type {
	case EnumPendingTransaction:
		o.Inner = &PendingTransaction{}
	case EnumUserTransaction:
		o.Inner = &UserTransaction{}
	case EnumGenesisTransaction:
		o.Inner = &GenesisTransaction{}
	case EnumBlockMetadataTransaction:
		o.Inner = &BlockMetadataTransaction{}
	case EnumStateCheckpointTransaction:
		o.Inner = &StateCheckpointTransaction{}
	case EnumValidatorTransaction:
		o.Inner = &ValidatorTransaction{}
	default:
		return fmt.Errorf("unknown transaction type: %s", o.Type)
	}
	return json.Unmarshal(b, o.Inner)
}

type TransactionImpl interface {
}

// UserTransaction is a user submitted transaction as an entry function or script
type UserTransaction struct {
	Version                 uint64
	Hash                    Hash
	AccumulatorRootHash     Hash
	StateChangeHash         Hash
	EventRootHash           Hash
	GasUsed                 uint64
	Success                 bool
	VmStatus                string
	Changes                 []*WriteSetChange
	Events                  []*Event
	Sender                  *types.AccountAddress
	SequenceNumber          uint64
	MaxGasAmount            uint64
	GasUnitPrice            uint64
	ExpirationTimestampSecs uint64
	Payload                 *TransactionPayload
	Signature               *Signature
	Timestamp               uint64 // TODO: native time?
	StateCheckpointHash     Hash   //Optional
}

func (o *UserTransaction) UnmarshalJSON(b []byte) error {
	type inner struct {
		Version                 U64                   `json:"version"`
		Hash                    Hash                  `json:"hash"`
		AccumulatorRootHash     Hash                  `json:"accumulator_root_hash"`
		StateChangeHash         Hash                  `json:"state_change_hash"`
		EventRootHash           Hash                  `json:"event_root_hash"`
		GasUsed                 U64                   `json:"gas_used"`
		Success                 bool                  `json:"success"`
		VmStatus                string                `json:"vm_status"`
		Changes                 []*WriteSetChange     `json:"changes"`
		Events                  []*Event              `json:"events"`
		Sender                  *types.AccountAddress `json:"sender"`
		SequenceNumber          U64                   `json:"sequence_number"`
		MaxGasAmount            U64                   `json:"max_gas_amount"`
		GasUnitPrice            U64                   `json:"gas_unit_price"`
		ExpirationTimestampSecs U64                   `json:"expiration_timestamp_secs"`
		Payload                 *TransactionPayload   `json:"payload"`
		Signature               *Signature            `json:"signature"`
		Timestamp               U64                   `json:"timestamp"`
		StateCheckpointHash     Hash                  `json:"state_checkpoint_hash"` // Optional
	}
	data := &inner{}
	err := json.Unmarshal(b, &data)
	if err != nil {
		return err
	}
	o.Version = data.Version.toUint64()
	o.Hash = data.Hash
	o.AccumulatorRootHash = data.AccumulatorRootHash
	o.StateChangeHash = data.StateChangeHash
	o.EventRootHash = data.EventRootHash
	o.GasUsed = data.GasUsed.toUint64()
	o.Success = data.Success
	o.VmStatus = data.VmStatus
	o.Changes = data.Changes
	o.Events = data.Events
	o.Sender = data.Sender
	o.SequenceNumber = data.SequenceNumber.toUint64()
	o.MaxGasAmount = data.MaxGasAmount.toUint64()
	o.GasUnitPrice = data.GasUnitPrice.toUint64()
	o.ExpirationTimestampSecs = data.ExpirationTimestampSecs.toUint64()
	o.Payload = data.Payload
	o.Signature = data.Signature
	o.Timestamp = data.Timestamp.toUint64()
	o.StateCheckpointHash = data.StateCheckpointHash
	return nil
}

type PendingTransaction struct {
	Hash                    string
	Sender                  *types.AccountAddress
	SequenceNumber          uint64
	MaxGasAmount            uint64
	GasUnitPrice            uint64
	ExpirationTimestampSecs uint64
	Payload                 *TransactionPayload
	Signature               *Signature
}

func (o *PendingTransaction) UnmarshalJSON(b []byte) error {
	type inner struct {
		Hash                    Hash                  `json:"hash"`
		Sender                  *types.AccountAddress `json:"sender"`
		SequenceNumber          U64                   `json:"sequence_number"`
		MaxGasAmount            U64                   `json:"max_gas_amount"`
		GasUnitPrice            U64                   `json:"gas_unit_price"`
		ExpirationTimestampSecs U64                   `json:"expiration_timestamp_secs"`
		Payload                 *TransactionPayload   `json:"payload"`
		Signature               *Signature            `json:"signature"`
	}
	data := &inner{}
	err := json.Unmarshal(b, &data)
	if err != nil {
		return err
	}
	o.Hash = data.Hash
	o.Sender = data.Sender
	o.SequenceNumber = data.SequenceNumber.toUint64()
	o.MaxGasAmount = data.MaxGasAmount.toUint64()
	o.GasUnitPrice = data.GasUnitPrice.toUint64()
	o.ExpirationTimestampSecs = data.ExpirationTimestampSecs.toUint64()
	o.Payload = data.Payload
	o.Signature = data.Signature
	return nil
}

type GenesisTransaction struct {
	Version             uint64
	Hash                Hash
	AccumulatorRootHash Hash
	StateChangeHash     Hash
	EventRootHash       Hash
	GasUsed             uint64
	Success             bool
	VmStatus            string
	Changes             []*WriteSetChange
	Events              []*Event
	Payload             *TransactionPayload
	StateCheckpointHash Hash // Optional
}

func (o *GenesisTransaction) UnmarshalJSON(b []byte) error {
	type inner struct {
		Version             U64                 `json:"version"`
		Hash                Hash                `json:"hash"`
		AccumulatorRootHash Hash                `json:"accumulator_root_hash"`
		StateChangeHash     Hash                `json:"state_change_hash"`
		EventRootHash       Hash                `json:"event_root_hash"`
		GasUsed             U64                 `json:"gas_used"`
		Success             bool                `json:"success"`
		VmStatus            string              `json:"vm_status"`
		Changes             []*WriteSetChange   `json:"changes"`
		Events              []*Event            `json:"events"`
		Payload             *TransactionPayload `json:"payload"`
		StateCheckpointHash Hash                `json:"state_checkpoint_hash"` // Optional
	}
	data := &inner{}
	err := json.Unmarshal(b, &data)
	if err != nil {
		return err
	}
	o.Version = data.Version.toUint64()
	o.Hash = data.Hash
	o.AccumulatorRootHash = data.AccumulatorRootHash
	o.StateChangeHash = data.StateChangeHash
	o.EventRootHash = data.EventRootHash
	o.GasUsed = data.GasUsed.toUint64()
	o.Success = data.Success
	o.VmStatus = data.VmStatus
	o.Changes = data.Changes
	o.Events = data.Events
	o.Payload = data.Payload
	o.StateCheckpointHash = data.StateCheckpointHash
	return nil
}

type BlockMetadataTransaction struct {
	Id                       string
	Epoch                    uint64
	Round                    uint64
	PreviousBlockVotesBitvec []uint8
	Proposer                 *types.AccountAddress
	FailedProposerIndices    []uint32
	Version                  uint64
	Hash                     string
	AccumulatorRootHash      Hash
	StateChangeHash          Hash
	EventRootHash            Hash
	GasUsed                  uint64
	Success                  bool
	VmStatus                 string
	Changes                  []*WriteSetChange
	Events                   []*Event
	Timestamp                uint64
	StateCheckpointHash      Hash
}

func (o *BlockMetadataTransaction) UnmarshalJSON(b []byte) error {
	type inner struct {
		Id                       string                `json:"id"`
		Epoch                    U64                   `json:"epoch"`
		Round                    U64                   `json:"round"`
		PreviousBlockVotesBitvec []byte                `json:"previous_block_votes_bitvec"` // TODO: this had to be float64 earlier
		Proposer                 *types.AccountAddress `json:"proposer"`
		FailedProposerIndices    []uint32              `json:"failed_proposer_indices"` // TODO: verify
		Version                  U64                   `json:"version"`
		Hash                     Hash                  `json:"hash"`
		AccumulatorRootHash      Hash                  `json:"accumulator_root_hash"`
		StateChangeHash          Hash                  `json:"state_change_hash"`
		EventRootHash            Hash                  `json:"event_root_hash"`
		GasUsed                  U64                   `json:"gas_used"`
		Success                  bool                  `json:"success"`
		VmStatus                 string                `json:"vm_status"`
		Changes                  []*WriteSetChange     `json:"changes"`
		Events                   []*Event              `json:"events"`
		Timestamp                U64                   `json:"timestamp"`
		StateCheckpointHash      Hash                  `json:"state_checkpoint_hash,omitempty"` // Optional
	}
	data := &inner{}
	err := json.Unmarshal(b, &data)
	if err != nil {
		return err
	}

	o.Id = data.Id
	o.Epoch = data.Epoch.toUint64()
	o.Round = data.Round.toUint64()
	o.PreviousBlockVotesBitvec = data.PreviousBlockVotesBitvec
	o.Proposer = data.Proposer
	o.FailedProposerIndices = data.FailedProposerIndices
	o.Version = data.Version.toUint64()
	o.Hash = data.Hash
	o.AccumulatorRootHash = data.AccumulatorRootHash
	o.StateChangeHash = data.StateChangeHash
	o.EventRootHash = data.EventRootHash
	o.GasUsed = data.GasUsed.toUint64()
	o.Success = data.Success
	o.VmStatus = data.VmStatus
	o.Changes = data.Changes
	o.Events = data.Events
	o.Timestamp = data.Timestamp.toUint64()
	o.StateCheckpointHash = data.StateCheckpointHash
	return nil
}

type StateCheckpointTransaction struct {
	Version             uint64
	Hash                Hash
	AccumulatorRootHash Hash
	StateChangeHash     Hash
	EventRootHash       Hash
	GasUsed             uint64
	Success             bool
	VmStatus            string
	Changes             []*WriteSetChange
	Timestamp           uint64
	StateCheckpointHash Hash // This is optional
}

func (o *StateCheckpointTransaction) UnmarshalJSON(b []byte) error {
	type inner struct {
		Version             U64               `json:"version"`
		Hash                Hash              `json:"hash"`
		AccumulatorRootHash Hash              `json:"accumulator_root_hash"`
		StateChangeHash     Hash              `json:"state_change_hash"`
		EventRootHash       Hash              `json:"event_root_hash"`
		GasUsed             U64               `json:"gas_used"`
		Success             bool              `json:"success"`
		VmStatus            string            `json:"vm_status"`
		Changes             []*WriteSetChange `json:"changes"`
		Timestamp           U64               `json:"timestamp"`
		StateCheckpointHash Hash              `json:"state_checkpoint_hash"` // Optional
	}
	data := &inner{}
	err := json.Unmarshal(b, &data)
	if err != nil {
		return err
	}

	o.Version = data.Version.toUint64()
	o.Hash = data.Hash
	o.AccumulatorRootHash = data.AccumulatorRootHash
	o.StateChangeHash = data.StateChangeHash
	o.EventRootHash = data.EventRootHash
	o.GasUsed = data.GasUsed.toUint64()
	o.Success = data.Success
	o.VmStatus = data.VmStatus
	o.Changes = data.Changes
	o.Timestamp = data.Timestamp.toUint64()
	o.StateCheckpointHash = data.StateCheckpointHash
	return nil
}

type ValidatorTransaction struct {
	Version             uint64
	Hash                Hash
	AccumulatorRootHash Hash
	StateChangeHash     Hash
	EventRootHash       Hash
	GasUsed             uint64
	Success             bool
	VmStatus            string
	Changes             []*WriteSetChange
	Events              []*Event
	Timestamp           uint64
	StateCheckpointHash Hash // This is optional
}

func (o *ValidatorTransaction) UnmarshalJSON(b []byte) error {
	type inner struct {
		Version             U64               `json:"version"`
		Hash                Hash              `json:"hash"`
		AccumulatorRootHash Hash              `json:"accumulator_root_hash"`
		StateChangeHash     Hash              `json:"state_change_hash"`
		EventRootHash       Hash              `json:"event_root_hash"`
		GasUsed             U64               `json:"gas_used"`
		Success             bool              `json:"success"`
		VmStatus            string            `json:"vm_status"`
		Changes             []*WriteSetChange `json:"changes"`
		Events              []*Event          `json:"events"`
		Timestamp           U64               `json:"timestamp"`
		StateCheckpointHash Hash              `json:"state_checkpoint_hash"` // Optional
	}
	data := &inner{}
	err := json.Unmarshal(b, &data)
	if err != nil {
		return err
	}
	o.Version = data.Version.toUint64()
	o.Hash = data.Hash
	o.AccumulatorRootHash = data.AccumulatorRootHash
	o.StateChangeHash = data.StateChangeHash
	o.EventRootHash = data.EventRootHash
	o.GasUsed = data.GasUsed.toUint64()
	o.Success = data.Success
	o.VmStatus = data.VmStatus
	o.Changes = data.Changes
	o.Events = data.Events
	o.Timestamp = data.Timestamp.toUint64()
	o.StateCheckpointHash = data.StateCheckpointHash

	return nil
}
