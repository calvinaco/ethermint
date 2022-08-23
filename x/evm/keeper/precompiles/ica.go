package precompiles

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	capabilitykeeper "github.com/cosmos/cosmos-sdk/x/capability/keeper"
	icacontrollerkeeper "github.com/cosmos/ibc-go/v3/modules/apps/27-interchain-accounts/controller/keeper"
	icatypes "github.com/cosmos/ibc-go/v3/modules/apps/27-interchain-accounts/types"
	ibcchannelkeeper "github.com/cosmos/ibc-go/v3/modules/core/04-channel/keeper"
	host "github.com/cosmos/ibc-go/v3/modules/core/24-host"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/evmos/ethermint/x/evm/statedb"
)

var (
	RegisterAccountMethod               abi.Method
	QueryAccountMethod                  abi.Method
	QueryAccountOpenActiveChannelMethod abi.Method
	SubmitMsgsMethod                    abi.Method

	_ statedb.StatefulPrecompiledContract = (*IcaContract)(nil)
	_ statedb.JournalEntry                = icaJournalEntry{}
)

func init() {
	addressType, _ := abi.NewType("address", "", nil)
	stringType, _ := abi.NewType("string", "", nil)
	uint256Type, _ := abi.NewType("uint256", "", nil)
	RegisterAccountMethod = abi.NewMethod(
		"registerAccount", "registerAccount", abi.Function, "", false, false, abi.Arguments{abi.Argument{
			Name: "connectionID",
			Type: stringType,
		}, abi.Argument{
			Name: "owner",
			Type: addressType,
		}},
		nil,
	)
	QueryAccountMethod = abi.NewMethod(
		"queryAccount", "queryAccount", abi.Function, "", false, false, abi.Arguments{abi.Argument{
			Name: "connectionID",
			Type: stringType,
		}, abi.Argument{
			Name: "owner",
			Type: addressType,
		}},
		abi.Arguments{abi.Argument{
			Name: "icaAccount",
			Type: stringType,
		}},
	)
	QueryAccountOpenActiveChannelMethod = abi.NewMethod(
		"queryAccountOpenActiveChannel", "queryAccountOpenActiveChannel", abi.Function, "", false, false, abi.Arguments{abi.Argument{
			Name: "connectionID",
			Type: stringType,
		}, abi.Argument{
			Name: "owner",
			Type: addressType,
		}},
		abi.Arguments{abi.Argument{
			Name: "channelID",
			Type: stringType,
		}},
	)
	SubmitMsgsMethod = abi.NewMethod(
		"submitMsgs", "submitMsgs", abi.Function, "", false, false, abi.Arguments{abi.Argument{
			Name: "connectionID",
			Type: stringType,
		}, abi.Argument{
			Name: "owner",
			Type: addressType,
		}, abi.Argument{
			Name: "msgs",
			Type: stringType,
		}, abi.Argument{
			Name: "timeout",
			Type: uint256Type,
		}},
		abi.Arguments{abi.Argument{
			Name: "channelID",
			Type: stringType,
		}, abi.Argument{
			Name: "packetSequence",
			Type: uint256Type,
		}},
	)
}

type IcaContract struct {
	ctx                 sdk.Context
	cdc                 codec.BinaryCodec
	protoCodec          *codec.ProtoCodec
	channelKeeper       *ibcchannelkeeper.Keeper
	icaControllerKeeper *icacontrollerkeeper.Keeper
	scopedKeeper        *capabilitykeeper.ScopedKeeper
	callbacks           ICAModule

	msgs []icaMessage
}

func NewIcaContractCreator(
	cdc codec.BinaryCodec,
	interfaceRegistry types.InterfaceRegistry,
	channelKeeper *ibcchannelkeeper.Keeper,
	icaControllerKeeper *icacontrollerkeeper.Keeper,
	scopedKeeper *capabilitykeeper.ScopedKeeper,
	callbacks ICAModule,
) statedb.PrecompiledContractCreator {
	protoCodec := codec.NewProtoCodec(interfaceRegistry)
	return func(ctx sdk.Context) statedb.StatefulPrecompiledContract {
		msgs := make([]icaMessage, 0)
		return &IcaContract{
			ctx,
			cdc,
			protoCodec,
			channelKeeper,
			icaControllerKeeper,
			scopedKeeper,
			callbacks,
			msgs,
		}
	}
}

// RequiredGas calculates the contract gas use
func (ic *IcaContract) RequiredGas(input []byte) uint64 {
	// TODO estimate required gas
	return 0
}

func (ic *IcaContract) Run(evm *vm.EVM, input []byte, caller common.Address, value *big.Int, readonly bool) ([]byte, error) {
	stateDB, ok := evm.StateDB.(ExtStateDB)
	if !ok {
		return nil, errors.New("not run in ethermint")
	}
	methodID := input[:4]
	switch string(methodID) {
	case string(RegisterAccountMethod.ID):
		if readonly {
			return nil, errors.New("the method is not readonly")
		}
		args, err := RegisterAccountMethod.Inputs.Unpack(input[4:])
		if err != nil {
			return nil, errors.New("fail to unpack input arguments")
		}
		connectionID := args[0].(string)
		account := args[1].(common.Address)
		evmTxSender := evm.TxContext.Origin
		evm.Origin.Hash()

		if !isSameAddress(account, caller) && !isSameAddress(account, evmTxSender) {
			return nil, errors.New("unauthorized account registration")
		}
		msg := &icaRegisterAccountMessage{
			icaMessageBase{
				ctx: ModuleContext{
					Caller:   caller,
					TxSender: evmTxSender,
				},
				dirty: false,
			},
			connectionID,
			account,
		}
		ic.msgs = append(ic.msgs, msg)
		stateDB.AppendJournalEntry(icaJournalEntry{ic, caller, evmTxSender, msg})

		fmt.Printf(
			"RegisterAccountMethod connectionId: %s, account: %s\n",
			connectionID, account,
		)
		return nil, nil
	case string(QueryAccountMethod.ID):
		args, err := QueryAccountMethod.Inputs.Unpack(input[4:])
		if err != nil {
			return nil, errors.New("fail to unpack input arguments")
		}

		connectionID := args[0].(string)
		account := args[1].(common.Address)

		owner := sdk.AccAddress(common.HexToAddress(account.String()).Bytes())
		portID, err := icatypes.NewControllerPortID(owner.String())
		if err != nil {
			return nil, fmt.Errorf("invalid owner address: %s", err)
		}
		fmt.Printf(
			"QueryAccountMethod connectionId: %s, account: %s\n",
			connectionID, account,
		)

		icaAddress, found := ic.icaControllerKeeper.GetInterchainAccountAddress(ic.ctx, connectionID, portID)
		if !found {
			return QueryAccountMethod.Outputs.Pack("")
		}

		return QueryAccountMethod.Outputs.Pack(icaAddress)
	case string(QueryAccountOpenActiveChannelMethod.ID):
		args, err := QueryAccountMethod.Inputs.Unpack(input[4:])
		if err != nil {
			return nil, errors.New("fail to unpack input arguments")
		}

		connectionID := args[0].(string)
		owner := args[1].(common.Address)

		portID, err := icatypes.NewControllerPortID(sdk.AccAddress(common.HexToAddress(owner.String()).Bytes()).String())
		if err != nil {
			return nil, fmt.Errorf("invalid owner address: %s", err)
		}

		channelID, found := ic.icaControllerKeeper.GetOpenActiveChannel(ic.ctx, connectionID, portID)
		fmt.Printf(
			"QueryAccountOpenActiveChannelMethod connectionId: %s, owner: %s\n",
			connectionID, owner,
		)

		if !found {
			return QueryAccountOpenActiveChannelMethod.Outputs.Pack("")
		}
		return QueryAccountOpenActiveChannelMethod.Outputs.Pack(channelID)
	case string(SubmitMsgsMethod.ID):
		if readonly {
			return nil, errors.New("the method is not readonly")
		}
		args, err := SubmitMsgsMethod.Inputs.Unpack(input[4:])
		if err != nil {
			return nil, errors.New("fail to unpack input arguments")
		}
		connectionID := args[0].(string)
		owner := args[1].(common.Address)
		msgs := args[2].(string)
		timeout := args[3].(*big.Int)
		evmTxSender := evm.TxContext.Origin

		if !isSameAddress(owner, caller) && !isSameAddress(owner, evmTxSender) {
			fmt.Println("unauthorized account registration")
			return nil, errors.New("unauthorized account registration")
		}

		var rawSdkMsgs []json.RawMessage
		if err := json.Unmarshal([]byte(msgs), &rawSdkMsgs); err != nil {
			fmt.Printf("invalid Cosmos messages: %s\n", err)
			return nil, fmt.Errorf("invalid Cosmos messages: %s", err)
		}
		sdkMsgs := make([]sdk.Msg, len(rawSdkMsgs))
		for i, rawSdkMsg := range rawSdkMsgs {
			var sdkMsg sdk.Msg
			if err := ic.protoCodec.UnmarshalInterfaceJSON([]byte(rawSdkMsg), &sdkMsg); err != nil {
				fmt.Printf("invalid Cosmos messages: %s\n", err)
				return nil, fmt.Errorf("invalid Cosmos messages: %s", err)
			}
			sdkMsgs[i] = sdkMsg
		}
		timeoutTimestamp := uint64(ic.ctx.BlockTime().UnixNano()) + timeout.Uint64()

		portID, err := icatypes.NewControllerPortID(sdk.AccAddress(common.HexToAddress(owner.String()).Bytes()).String())
		if err != nil {
			fmt.Printf("invalid owner address: %s", err)
			return nil, fmt.Errorf("invalid owner address: %s", err)
		}
		channelID, found := ic.icaControllerKeeper.GetOpenActiveChannel(ic.ctx, connectionID, portID)
		if !found {
			fmt.Printf("failed to retrieve active channel for port %s", portID)
			return nil, fmt.Errorf("failed to retrieve active channel for port %s", portID)
		}

		// FIXME: keep track of next sequence for each portId-channelId
		packetSequence, _ := ic.channelKeeper.GetNextSequenceSend(ic.ctx, portID, channelID)

		msg := &icaSubmitMsgsMessage{
			icaMessageBase: icaMessageBase{
				ctx: ModuleContext{
					Caller:   caller,
					TxSender: evmTxSender,
				},
				dirty: false,
			},
			connectionID:           connectionID,
			owner:                  owner,
			msgs:                   sdkMsgs,
			timeoutTimestamp:       timeoutTimestamp,
			expectedPacketSequence: packetSequence,
		}
		ic.msgs = append(ic.msgs, msg)
		stateDB.AppendJournalEntry(icaJournalEntry{ic, caller, evmTxSender, msg})

		fmt.Printf(
			"SubmitMsgsMethod connectionId: %s, owner: %s, msgs: %s, timeoutTimestamp: %d, expectedPacketSequence: %d\n",
			connectionID, owner, msgs, timeoutTimestamp, packetSequence,
		)
		return SubmitMsgsMethod.Outputs.Pack(channelID, new(big.Int).SetUint64(packetSequence))

	default:
		return nil, errors.New("unknown method")
	}
}

func (ic *IcaContract) Commit(ctx sdk.Context) error {
	fmt.Println("ica precompile commit phase")
	for _, msg := range ic.msgs {
		if msg.isDirty() {
			continue
		}

		switch msg.messageType() {
		case icaRegisterAccountMessageType:
			typedMessage := msg.(*icaRegisterAccountMessage)
			owner := sdk.AccAddress(common.HexToAddress(typedMessage.owner.String()).Bytes()).String()
			fmt.Printf(
				"RegisterAccountMethod going to be committed connectionID: %s, account: %s\n",
				typedMessage.connectionID, typedMessage.owner,
			)
			if err := ic.icaControllerKeeper.RegisterInterchainAccount(ic.ctx, typedMessage.connectionID, owner); err != nil {
				fmt.Println(err)
				return err
			}
			if err := ic.callbacks.OnRegisterInterchainAccount(ic.ctx, msg.context(), typedMessage.connectionID, owner); err != nil {
				fmt.Println(err)
				return err
			}

			return nil
		case icaSubmitMsgsMessageType:
			typedMessage := msg.(*icaSubmitMsgsMessage)
			owner := sdk.AccAddress(common.HexToAddress(typedMessage.owner.String()).Bytes()).String()

			portID, err := icatypes.NewControllerPortID(owner)
			if err != nil {
				fmt.Printf("invalid owner address: %s\n", err)
				return fmt.Errorf("invalid owner address: %s", err)
			}

			channelID, found := ic.icaControllerKeeper.GetOpenActiveChannel(ctx, typedMessage.connectionID, portID)
			if !found {
				fmt.Printf("failed to retrieve active open channel of connection: %s, port %s\n", typedMessage.connectionID, portID)
				return fmt.Errorf("failed to retrieve active open channel of connection: %s, port %s", typedMessage.connectionID, portID)
			}

			channelCapability, found := ic.scopedKeeper.GetCapability(ctx, host.ChannelCapabilityPath(portID, channelID))
			if !found {
				fmt.Println("module does not own channel capability")
				return errors.New("module does not own channel capability")
			}

			data, err := icatypes.SerializeCosmosTx(ic.cdc, typedMessage.msgs)
			if err != nil {
				fmt.Printf("failed to serialize Cosmos Tx from messages: %s\n", err)
				return fmt.Errorf("failed to serialize Cosmos Tx from messages: %s", err)
			}

			packetData := icatypes.InterchainAccountPacketData{
				Type: icatypes.EXECUTE_TX,
				Data: data,
			}

			fmt.Printf(
				"SubmitMsgsMethod sending ICA transaction with connectionID %s, portID: %s, packetData: %s, timeoutTimestamp: %d\n",
				typedMessage.connectionID, portID, packetData, typedMessage.timeoutTimestamp,
			)
			packetSequence, err := ic.icaControllerKeeper.SendTx(ctx, channelCapability, typedMessage.connectionID, portID, packetData, typedMessage.timeoutTimestamp)
			if err != nil {
				fmt.Printf("failed to send ICA transaction: %s\n", err)
				return fmt.Errorf("failed to send ICA transaction: %s", err)
			}

			// failsafe for multi-precompile race conditions
			// if a contract calls multiple precompiles that send IBC packets to the same connection and port, the
			// packet sequence returned to the contract could be wrong as each precompile has no knowledge of each other
			if packetSequence != typedMessage.expectedPacketSequence {
				return fmt.Errorf("packet sequence mismatched, expected: %d, actual: %d", typedMessage.expectedPacketSequence, packetSequence)
			}

			return ic.callbacks.OnSendTx(
				ctx, msg.context(), channelCapability, typedMessage.connectionID, channelID, portID, packetData, typedMessage.timeoutTimestamp, packetSequence,
			)
		}
	}
	return nil
}

type icaJournalEntry struct {
	ic          *IcaContract
	caller      common.Address
	evmTxSender common.Address
	msg         icaMessage
}

func (entry icaJournalEntry) Revert(*statedb.StateDB) {
	entry.msg.setDirty(true)
}

func (entry icaJournalEntry) Dirtied() *common.Address {
	return nil
}

type icaMessage interface {
	context() ModuleContext
	messageType() string
	setDirty(bool)
	isDirty() bool
}

type icaMessageBase struct {
	ctx   ModuleContext
	dirty bool
}

func (base *icaMessageBase) context() ModuleContext {
	return base.ctx
}
func (base *icaMessageBase) setDirty(dirty bool) {
	base.dirty = dirty
}
func (base *icaMessageBase) isDirty() bool {
	return base.dirty
}

const icaRegisterAccountMessageType = "RegisterAccount"
const icaSubmitMsgsMessageType = "SubmitMsgs"

var _ icaMessage = &icaRegisterAccountMessage{}

type icaRegisterAccountMessage struct {
	icaMessageBase
	connectionID string
	owner        common.Address
}

func (msg icaRegisterAccountMessage) messageType() string {
	return icaRegisterAccountMessageType
}

var _ icaMessage = &icaSubmitMsgsMessage{}

type icaSubmitMsgsMessage struct {
	icaMessageBase
	connectionID           string
	owner                  common.Address
	msgs                   []sdk.Msg
	timeoutTimestamp       uint64
	expectedPacketSequence uint64
}

func (msg icaSubmitMsgsMessage) messageType() string {
	return icaSubmitMsgsMessageType
}

func isSameAddress(a common.Address, b common.Address) bool {
	return bytes.Compare(a.Bytes(), b.Bytes()) == 0
}
