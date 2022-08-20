package precompiles

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	capabilitytypes "github.com/cosmos/cosmos-sdk/x/capability/types"
	icatypes "github.com/cosmos/ibc-go/v3/modules/apps/27-interchain-accounts/types"
	"github.com/ethereum/go-ethereum/common"
)

// ICAModule defines an interface that implements all the callbacks
// for ICA contract
type ICAModule interface {
	OnRegisterInterchainAccount(
		ctx sdk.Context,
		precompileCtx ModuleContext,
		connectionID string,
		owner string,
	) error

	OnSendTx(
		ctx sdk.Context,
		precompileCtx ModuleContext,
		chanCap *capabilitytypes.Capability,
		connectionID string,
		channelID string,
		portID string,
		icaPacketData icatypes.InterchainAccountPacketData,
		timeoutTimestamp uint64,
		packetSequence uint64,
	) error
}

type ModuleContext struct {
	Caller   common.Address
	TxSender common.Address
}
