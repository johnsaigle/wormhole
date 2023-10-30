import type { BaseContract, BigNumberish, BytesLike, FunctionFragment, Result, Interface, EventFragment, AddressLike, ContractRunner, ContractMethod, Listener } from 'ethers';
import type { TypedContractEvent, TypedDeferredTopicFilter, TypedEventLog, TypedLogDescription, TypedListener, TypedContractMethod } from './common';
export declare namespace TokenBridgeRelayerStructs {
    type SwapRateUpdateStruct = {
        token: AddressLike;
        value: BigNumberish;
    };
    type SwapRateUpdateStructOutput = [token: string, value: bigint] & {
        token: string;
        value: bigint;
    };
    type TransferWithRelayStruct = {
        payloadId: BigNumberish;
        targetRelayerFee: BigNumberish;
        toNativeTokenAmount: BigNumberish;
        targetRecipient: BytesLike;
    };
    type TransferWithRelayStructOutput = [
        payloadId: bigint,
        targetRelayerFee: bigint,
        toNativeTokenAmount: bigint,
        targetRecipient: string
    ] & {
        payloadId: bigint;
        targetRelayerFee: bigint;
        toNativeTokenAmount: bigint;
        targetRecipient: string;
    };
}
export interface TokenBridgeRelayerInterface extends Interface {
    getFunction(nameOrSignature: 'VERSION' | 'WETH' | 'calculateMaxSwapAmountIn' | 'calculateNativeSwapAmountOut' | 'calculateRelayerFee' | 'cancelOwnershipTransferRequest' | 'chainId' | 'completeTransferWithRelay' | 'confirmOwnershipTransferRequest' | 'decodeTransferWithRelay' | 'denormalizeAmount' | 'deregisterToken' | 'encodeTransferWithRelay' | 'feeRecipient' | 'fetchLocalAddressFromTransferMessage' | 'getAcceptedTokensList' | 'getPaused' | 'getRegisteredContract' | 'isAcceptedToken' | 'maxNativeSwapAmount' | 'nativeSwapRate' | 'normalizeAmount' | 'owner' | 'ownerAssistant' | 'pendingOwner' | 'registerContract' | 'registerToken' | 'relayerFee' | 'relayerFeePrecision' | 'setPauseForTransfers' | 'submitOwnershipTransferRequest' | 'swapRate' | 'swapRatePrecision' | 'tokenBridge' | 'transferTokensWithRelay' | 'unwrapWeth' | 'updateFeeRecipient' | 'updateMaxNativeSwapAmount' | 'updateOwnerAssistant' | 'updateRelayerFee' | 'updateRelayerFeePrecision' | 'updateSwapRate' | 'updateSwapRatePrecision' | 'updateUnwrapWethFlag' | 'wormhole' | 'wrapAndTransferEthWithRelay'): FunctionFragment;
    getEvent(nameOrSignatureOrTopic: 'FeeRecipientUpdated' | 'OwnershipTransfered' | 'SwapExecuted' | 'SwapRateUpdated' | 'TransferRedeemed'): EventFragment;
    encodeFunctionData(functionFragment: 'VERSION', values?: undefined): string;
    encodeFunctionData(functionFragment: 'WETH', values?: undefined): string;
    encodeFunctionData(functionFragment: 'calculateMaxSwapAmountIn', values: [AddressLike]): string;
    encodeFunctionData(functionFragment: 'calculateNativeSwapAmountOut', values: [AddressLike, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'calculateRelayerFee', values: [BigNumberish, AddressLike, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'cancelOwnershipTransferRequest', values: [BigNumberish]): string;
    encodeFunctionData(functionFragment: 'chainId', values?: undefined): string;
    encodeFunctionData(functionFragment: 'completeTransferWithRelay', values: [BytesLike]): string;
    encodeFunctionData(functionFragment: 'confirmOwnershipTransferRequest', values?: undefined): string;
    encodeFunctionData(functionFragment: 'decodeTransferWithRelay', values: [BytesLike]): string;
    encodeFunctionData(functionFragment: 'denormalizeAmount', values: [BigNumberish, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'deregisterToken', values: [BigNumberish, AddressLike]): string;
    encodeFunctionData(functionFragment: 'encodeTransferWithRelay', values: [TokenBridgeRelayerStructs.TransferWithRelayStruct]): string;
    encodeFunctionData(functionFragment: 'feeRecipient', values?: undefined): string;
    encodeFunctionData(functionFragment: 'fetchLocalAddressFromTransferMessage', values: [BytesLike]): string;
    encodeFunctionData(functionFragment: 'getAcceptedTokensList', values?: undefined): string;
    encodeFunctionData(functionFragment: 'getPaused', values?: undefined): string;
    encodeFunctionData(functionFragment: 'getRegisteredContract', values: [BigNumberish]): string;
    encodeFunctionData(functionFragment: 'isAcceptedToken', values: [AddressLike]): string;
    encodeFunctionData(functionFragment: 'maxNativeSwapAmount', values: [AddressLike]): string;
    encodeFunctionData(functionFragment: 'nativeSwapRate', values: [AddressLike]): string;
    encodeFunctionData(functionFragment: 'normalizeAmount', values: [BigNumberish, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'owner', values?: undefined): string;
    encodeFunctionData(functionFragment: 'ownerAssistant', values?: undefined): string;
    encodeFunctionData(functionFragment: 'pendingOwner', values?: undefined): string;
    encodeFunctionData(functionFragment: 'registerContract', values: [BigNumberish, BytesLike]): string;
    encodeFunctionData(functionFragment: 'registerToken', values: [BigNumberish, AddressLike]): string;
    encodeFunctionData(functionFragment: 'relayerFee', values: [BigNumberish]): string;
    encodeFunctionData(functionFragment: 'relayerFeePrecision', values?: undefined): string;
    encodeFunctionData(functionFragment: 'setPauseForTransfers', values: [BigNumberish, boolean]): string;
    encodeFunctionData(functionFragment: 'submitOwnershipTransferRequest', values: [BigNumberish, AddressLike]): string;
    encodeFunctionData(functionFragment: 'swapRate', values: [AddressLike]): string;
    encodeFunctionData(functionFragment: 'swapRatePrecision', values?: undefined): string;
    encodeFunctionData(functionFragment: 'tokenBridge', values?: undefined): string;
    encodeFunctionData(functionFragment: 'transferTokensWithRelay', values: [
        AddressLike,
        BigNumberish,
        BigNumberish,
        BigNumberish,
        BytesLike,
        BigNumberish
    ]): string;
    encodeFunctionData(functionFragment: 'unwrapWeth', values?: undefined): string;
    encodeFunctionData(functionFragment: 'updateFeeRecipient', values: [BigNumberish, AddressLike]): string;
    encodeFunctionData(functionFragment: 'updateMaxNativeSwapAmount', values: [BigNumberish, AddressLike, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'updateOwnerAssistant', values: [BigNumberish, AddressLike]): string;
    encodeFunctionData(functionFragment: 'updateRelayerFee', values: [BigNumberish, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'updateRelayerFeePrecision', values: [BigNumberish, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'updateSwapRate', values: [BigNumberish, TokenBridgeRelayerStructs.SwapRateUpdateStruct[]]): string;
    encodeFunctionData(functionFragment: 'updateSwapRatePrecision', values: [BigNumberish, BigNumberish]): string;
    encodeFunctionData(functionFragment: 'updateUnwrapWethFlag', values: [BigNumberish, boolean]): string;
    encodeFunctionData(functionFragment: 'wormhole', values?: undefined): string;
    encodeFunctionData(functionFragment: 'wrapAndTransferEthWithRelay', values: [BigNumberish, BigNumberish, BytesLike, BigNumberish]): string;
    decodeFunctionResult(functionFragment: 'VERSION', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'WETH', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'calculateMaxSwapAmountIn', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'calculateNativeSwapAmountOut', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'calculateRelayerFee', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'cancelOwnershipTransferRequest', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'chainId', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'completeTransferWithRelay', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'confirmOwnershipTransferRequest', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'decodeTransferWithRelay', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'denormalizeAmount', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'deregisterToken', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'encodeTransferWithRelay', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'feeRecipient', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'fetchLocalAddressFromTransferMessage', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getAcceptedTokensList', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getPaused', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'getRegisteredContract', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'isAcceptedToken', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'maxNativeSwapAmount', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'nativeSwapRate', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'normalizeAmount', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'owner', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'ownerAssistant', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'pendingOwner', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'registerContract', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'registerToken', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'relayerFee', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'relayerFeePrecision', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'setPauseForTransfers', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'submitOwnershipTransferRequest', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'swapRate', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'swapRatePrecision', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'tokenBridge', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'transferTokensWithRelay', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'unwrapWeth', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'updateFeeRecipient', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'updateMaxNativeSwapAmount', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'updateOwnerAssistant', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'updateRelayerFee', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'updateRelayerFeePrecision', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'updateSwapRate', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'updateSwapRatePrecision', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'updateUnwrapWethFlag', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'wormhole', data: BytesLike): Result;
    decodeFunctionResult(functionFragment: 'wrapAndTransferEthWithRelay', data: BytesLike): Result;
}
export declare namespace FeeRecipientUpdatedEvent {
    type InputTuple = [
        oldRecipient: AddressLike,
        newRecipient: AddressLike
    ];
    type OutputTuple = [oldRecipient: string, newRecipient: string];
    interface OutputObject {
        oldRecipient: string;
        newRecipient: string;
    }
    type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter<Event>;
    type Log = TypedEventLog<Event>;
    type LogDescription = TypedLogDescription<Event>;
}
export declare namespace OwnershipTransferedEvent {
    type InputTuple = [oldOwner: AddressLike, newOwner: AddressLike];
    type OutputTuple = [oldOwner: string, newOwner: string];
    interface OutputObject {
        oldOwner: string;
        newOwner: string;
    }
    type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter<Event>;
    type Log = TypedEventLog<Event>;
    type LogDescription = TypedLogDescription<Event>;
}
export declare namespace SwapExecutedEvent {
    type InputTuple = [
        recipient: AddressLike,
        relayer: AddressLike,
        token: AddressLike,
        tokenAmount: BigNumberish,
        nativeAmount: BigNumberish
    ];
    type OutputTuple = [
        recipient: string,
        relayer: string,
        token: string,
        tokenAmount: bigint,
        nativeAmount: bigint
    ];
    interface OutputObject {
        recipient: string;
        relayer: string;
        token: string;
        tokenAmount: bigint;
        nativeAmount: bigint;
    }
    type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter<Event>;
    type Log = TypedEventLog<Event>;
    type LogDescription = TypedLogDescription<Event>;
}
export declare namespace SwapRateUpdatedEvent {
    type InputTuple = [
        swapRates: TokenBridgeRelayerStructs.SwapRateUpdateStruct[]
    ];
    type OutputTuple = [
        swapRates: TokenBridgeRelayerStructs.SwapRateUpdateStructOutput[]
    ];
    interface OutputObject {
        swapRates: TokenBridgeRelayerStructs.SwapRateUpdateStructOutput[];
    }
    type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter<Event>;
    type Log = TypedEventLog<Event>;
    type LogDescription = TypedLogDescription<Event>;
}
export declare namespace TransferRedeemedEvent {
    type InputTuple = [
        emitterChainId: BigNumberish,
        emitterAddress: BytesLike,
        sequence: BigNumberish
    ];
    type OutputTuple = [
        emitterChainId: bigint,
        emitterAddress: string,
        sequence: bigint
    ];
    interface OutputObject {
        emitterChainId: bigint;
        emitterAddress: string;
        sequence: bigint;
    }
    type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
    type Filter = TypedDeferredTopicFilter<Event>;
    type Log = TypedEventLog<Event>;
    type LogDescription = TypedLogDescription<Event>;
}
export interface TokenBridgeRelayer extends BaseContract {
    connect(runner?: ContractRunner | null): TokenBridgeRelayer;
    waitForDeployment(): Promise<this>;
    interface: TokenBridgeRelayerInterface;
    queryFilter<TCEvent extends TypedContractEvent>(event: TCEvent, fromBlockOrBlockhash?: string | number | undefined, toBlock?: string | number | undefined): Promise<Array<TypedEventLog<TCEvent>>>;
    queryFilter<TCEvent extends TypedContractEvent>(filter: TypedDeferredTopicFilter<TCEvent>, fromBlockOrBlockhash?: string | number | undefined, toBlock?: string | number | undefined): Promise<Array<TypedEventLog<TCEvent>>>;
    on<TCEvent extends TypedContractEvent>(event: TCEvent, listener: TypedListener<TCEvent>): Promise<this>;
    on<TCEvent extends TypedContractEvent>(filter: TypedDeferredTopicFilter<TCEvent>, listener: TypedListener<TCEvent>): Promise<this>;
    once<TCEvent extends TypedContractEvent>(event: TCEvent, listener: TypedListener<TCEvent>): Promise<this>;
    once<TCEvent extends TypedContractEvent>(filter: TypedDeferredTopicFilter<TCEvent>, listener: TypedListener<TCEvent>): Promise<this>;
    listeners<TCEvent extends TypedContractEvent>(event: TCEvent): Promise<Array<TypedListener<TCEvent>>>;
    listeners(eventName?: string): Promise<Array<Listener>>;
    removeAllListeners<TCEvent extends TypedContractEvent>(event?: TCEvent): Promise<this>;
    VERSION: TypedContractMethod<[], [string], 'view'>;
    WETH: TypedContractMethod<[], [string], 'view'>;
    calculateMaxSwapAmountIn: TypedContractMethod<[
        token: AddressLike
    ], [
        bigint
    ], 'view'>;
    calculateNativeSwapAmountOut: TypedContractMethod<[
        token: AddressLike,
        toNativeAmount: BigNumberish
    ], [
        bigint
    ], 'view'>;
    calculateRelayerFee: TypedContractMethod<[
        targetChainId: BigNumberish,
        token: AddressLike,
        decimals: BigNumberish
    ], [
        bigint
    ], 'view'>;
    cancelOwnershipTransferRequest: TypedContractMethod<[
        chainId_: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    chainId: TypedContractMethod<[], [bigint], 'view'>;
    completeTransferWithRelay: TypedContractMethod<[
        encodedTransferMessage: BytesLike
    ], [
        void
    ], 'payable'>;
    confirmOwnershipTransferRequest: TypedContractMethod<[
    ], [
        void
    ], 'nonpayable'>;
    decodeTransferWithRelay: TypedContractMethod<[
        encoded: BytesLike
    ], [
        TokenBridgeRelayerStructs.TransferWithRelayStructOutput
    ], 'view'>;
    denormalizeAmount: TypedContractMethod<[
        amount: BigNumberish,
        decimals: BigNumberish
    ], [
        bigint
    ], 'view'>;
    deregisterToken: TypedContractMethod<[
        chainId_: BigNumberish,
        token: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    encodeTransferWithRelay: TypedContractMethod<[
        transfer: TokenBridgeRelayerStructs.TransferWithRelayStruct
    ], [
        string
    ], 'view'>;
    feeRecipient: TypedContractMethod<[], [string], 'view'>;
    fetchLocalAddressFromTransferMessage: TypedContractMethod<[
        payload: BytesLike
    ], [
        string
    ], 'view'>;
    getAcceptedTokensList: TypedContractMethod<[], [string[]], 'view'>;
    getPaused: TypedContractMethod<[], [boolean], 'view'>;
    getRegisteredContract: TypedContractMethod<[
        emitterChainId: BigNumberish
    ], [
        string
    ], 'view'>;
    isAcceptedToken: TypedContractMethod<[token: AddressLike], [boolean], 'view'>;
    maxNativeSwapAmount: TypedContractMethod<[
        token: AddressLike
    ], [
        bigint
    ], 'view'>;
    nativeSwapRate: TypedContractMethod<[token: AddressLike], [bigint], 'view'>;
    normalizeAmount: TypedContractMethod<[
        amount: BigNumberish,
        decimals: BigNumberish
    ], [
        bigint
    ], 'view'>;
    owner: TypedContractMethod<[], [string], 'view'>;
    ownerAssistant: TypedContractMethod<[], [string], 'view'>;
    pendingOwner: TypedContractMethod<[], [string], 'view'>;
    registerContract: TypedContractMethod<[
        chainId_: BigNumberish,
        contractAddress: BytesLike
    ], [
        void
    ], 'nonpayable'>;
    registerToken: TypedContractMethod<[
        chainId_: BigNumberish,
        token: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    relayerFee: TypedContractMethod<[chainId_: BigNumberish], [bigint], 'view'>;
    relayerFeePrecision: TypedContractMethod<[], [bigint], 'view'>;
    setPauseForTransfers: TypedContractMethod<[
        chainId_: BigNumberish,
        paused: boolean
    ], [
        void
    ], 'nonpayable'>;
    submitOwnershipTransferRequest: TypedContractMethod<[
        chainId_: BigNumberish,
        newOwner: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    swapRate: TypedContractMethod<[token: AddressLike], [bigint], 'view'>;
    swapRatePrecision: TypedContractMethod<[], [bigint], 'view'>;
    tokenBridge: TypedContractMethod<[], [string], 'view'>;
    transferTokensWithRelay: TypedContractMethod<[
        token: AddressLike,
        amount: BigNumberish,
        toNativeTokenAmount: BigNumberish,
        targetChain: BigNumberish,
        targetRecipient: BytesLike,
        batchId: BigNumberish
    ], [
        bigint
    ], 'payable'>;
    unwrapWeth: TypedContractMethod<[], [boolean], 'view'>;
    updateFeeRecipient: TypedContractMethod<[
        chainId_: BigNumberish,
        newFeeRecipient: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    updateMaxNativeSwapAmount: TypedContractMethod<[
        chainId_: BigNumberish,
        token: AddressLike,
        maxAmount: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    updateOwnerAssistant: TypedContractMethod<[
        chainId_: BigNumberish,
        newAssistant: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    updateRelayerFee: TypedContractMethod<[
        chainId_: BigNumberish,
        amount: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    updateRelayerFeePrecision: TypedContractMethod<[
        chainId_: BigNumberish,
        relayerFeePrecision_: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    updateSwapRate: TypedContractMethod<[
        chainId_: BigNumberish,
        swapRateUpdate: TokenBridgeRelayerStructs.SwapRateUpdateStruct[]
    ], [
        void
    ], 'nonpayable'>;
    updateSwapRatePrecision: TypedContractMethod<[
        chainId_: BigNumberish,
        swapRatePrecision_: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    updateUnwrapWethFlag: TypedContractMethod<[
        chainId_: BigNumberish,
        unwrapWeth_: boolean
    ], [
        void
    ], 'nonpayable'>;
    wormhole: TypedContractMethod<[], [string], 'view'>;
    wrapAndTransferEthWithRelay: TypedContractMethod<[
        toNativeTokenAmount: BigNumberish,
        targetChain: BigNumberish,
        targetRecipient: BytesLike,
        batchId: BigNumberish
    ], [
        bigint
    ], 'payable'>;
    getFunction<T extends ContractMethod = ContractMethod>(key: string | FunctionFragment): T;
    getFunction(nameOrSignature: 'VERSION'): TypedContractMethod<[], [string], 'view'>;
    getFunction(nameOrSignature: 'WETH'): TypedContractMethod<[], [string], 'view'>;
    getFunction(nameOrSignature: 'calculateMaxSwapAmountIn'): TypedContractMethod<[token: AddressLike], [bigint], 'view'>;
    getFunction(nameOrSignature: 'calculateNativeSwapAmountOut'): TypedContractMethod<[
        token: AddressLike,
        toNativeAmount: BigNumberish
    ], [
        bigint
    ], 'view'>;
    getFunction(nameOrSignature: 'calculateRelayerFee'): TypedContractMethod<[
        targetChainId: BigNumberish,
        token: AddressLike,
        decimals: BigNumberish
    ], [
        bigint
    ], 'view'>;
    getFunction(nameOrSignature: 'cancelOwnershipTransferRequest'): TypedContractMethod<[chainId_: BigNumberish], [void], 'nonpayable'>;
    getFunction(nameOrSignature: 'chainId'): TypedContractMethod<[], [bigint], 'view'>;
    getFunction(nameOrSignature: 'completeTransferWithRelay'): TypedContractMethod<[
        encodedTransferMessage: BytesLike
    ], [
        void
    ], 'payable'>;
    getFunction(nameOrSignature: 'confirmOwnershipTransferRequest'): TypedContractMethod<[], [void], 'nonpayable'>;
    getFunction(nameOrSignature: 'decodeTransferWithRelay'): TypedContractMethod<[
        encoded: BytesLike
    ], [
        TokenBridgeRelayerStructs.TransferWithRelayStructOutput
    ], 'view'>;
    getFunction(nameOrSignature: 'denormalizeAmount'): TypedContractMethod<[
        amount: BigNumberish,
        decimals: BigNumberish
    ], [
        bigint
    ], 'view'>;
    getFunction(nameOrSignature: 'deregisterToken'): TypedContractMethod<[
        chainId_: BigNumberish,
        token: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'encodeTransferWithRelay'): TypedContractMethod<[
        transfer: TokenBridgeRelayerStructs.TransferWithRelayStruct
    ], [
        string
    ], 'view'>;
    getFunction(nameOrSignature: 'feeRecipient'): TypedContractMethod<[], [string], 'view'>;
    getFunction(nameOrSignature: 'fetchLocalAddressFromTransferMessage'): TypedContractMethod<[payload: BytesLike], [string], 'view'>;
    getFunction(nameOrSignature: 'getAcceptedTokensList'): TypedContractMethod<[], [string[]], 'view'>;
    getFunction(nameOrSignature: 'getPaused'): TypedContractMethod<[], [boolean], 'view'>;
    getFunction(nameOrSignature: 'getRegisteredContract'): TypedContractMethod<[emitterChainId: BigNumberish], [string], 'view'>;
    getFunction(nameOrSignature: 'isAcceptedToken'): TypedContractMethod<[token: AddressLike], [boolean], 'view'>;
    getFunction(nameOrSignature: 'maxNativeSwapAmount'): TypedContractMethod<[token: AddressLike], [bigint], 'view'>;
    getFunction(nameOrSignature: 'nativeSwapRate'): TypedContractMethod<[token: AddressLike], [bigint], 'view'>;
    getFunction(nameOrSignature: 'normalizeAmount'): TypedContractMethod<[
        amount: BigNumberish,
        decimals: BigNumberish
    ], [
        bigint
    ], 'view'>;
    getFunction(nameOrSignature: 'owner'): TypedContractMethod<[], [string], 'view'>;
    getFunction(nameOrSignature: 'ownerAssistant'): TypedContractMethod<[], [string], 'view'>;
    getFunction(nameOrSignature: 'pendingOwner'): TypedContractMethod<[], [string], 'view'>;
    getFunction(nameOrSignature: 'registerContract'): TypedContractMethod<[
        chainId_: BigNumberish,
        contractAddress: BytesLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'registerToken'): TypedContractMethod<[
        chainId_: BigNumberish,
        token: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'relayerFee'): TypedContractMethod<[chainId_: BigNumberish], [bigint], 'view'>;
    getFunction(nameOrSignature: 'relayerFeePrecision'): TypedContractMethod<[], [bigint], 'view'>;
    getFunction(nameOrSignature: 'setPauseForTransfers'): TypedContractMethod<[
        chainId_: BigNumberish,
        paused: boolean
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'submitOwnershipTransferRequest'): TypedContractMethod<[
        chainId_: BigNumberish,
        newOwner: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'swapRate'): TypedContractMethod<[token: AddressLike], [bigint], 'view'>;
    getFunction(nameOrSignature: 'swapRatePrecision'): TypedContractMethod<[], [bigint], 'view'>;
    getFunction(nameOrSignature: 'tokenBridge'): TypedContractMethod<[], [string], 'view'>;
    getFunction(nameOrSignature: 'transferTokensWithRelay'): TypedContractMethod<[
        token: AddressLike,
        amount: BigNumberish,
        toNativeTokenAmount: BigNumberish,
        targetChain: BigNumberish,
        targetRecipient: BytesLike,
        batchId: BigNumberish
    ], [
        bigint
    ], 'payable'>;
    getFunction(nameOrSignature: 'unwrapWeth'): TypedContractMethod<[], [boolean], 'view'>;
    getFunction(nameOrSignature: 'updateFeeRecipient'): TypedContractMethod<[
        chainId_: BigNumberish,
        newFeeRecipient: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'updateMaxNativeSwapAmount'): TypedContractMethod<[
        chainId_: BigNumberish,
        token: AddressLike,
        maxAmount: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'updateOwnerAssistant'): TypedContractMethod<[
        chainId_: BigNumberish,
        newAssistant: AddressLike
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'updateRelayerFee'): TypedContractMethod<[
        chainId_: BigNumberish,
        amount: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'updateRelayerFeePrecision'): TypedContractMethod<[
        chainId_: BigNumberish,
        relayerFeePrecision_: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'updateSwapRate'): TypedContractMethod<[
        chainId_: BigNumberish,
        swapRateUpdate: TokenBridgeRelayerStructs.SwapRateUpdateStruct[]
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'updateSwapRatePrecision'): TypedContractMethod<[
        chainId_: BigNumberish,
        swapRatePrecision_: BigNumberish
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'updateUnwrapWethFlag'): TypedContractMethod<[
        chainId_: BigNumberish,
        unwrapWeth_: boolean
    ], [
        void
    ], 'nonpayable'>;
    getFunction(nameOrSignature: 'wormhole'): TypedContractMethod<[], [string], 'view'>;
    getFunction(nameOrSignature: 'wrapAndTransferEthWithRelay'): TypedContractMethod<[
        toNativeTokenAmount: BigNumberish,
        targetChain: BigNumberish,
        targetRecipient: BytesLike,
        batchId: BigNumberish
    ], [
        bigint
    ], 'payable'>;
    getEvent(key: 'FeeRecipientUpdated'): TypedContractEvent<FeeRecipientUpdatedEvent.InputTuple, FeeRecipientUpdatedEvent.OutputTuple, FeeRecipientUpdatedEvent.OutputObject>;
    getEvent(key: 'OwnershipTransfered'): TypedContractEvent<OwnershipTransferedEvent.InputTuple, OwnershipTransferedEvent.OutputTuple, OwnershipTransferedEvent.OutputObject>;
    getEvent(key: 'SwapExecuted'): TypedContractEvent<SwapExecutedEvent.InputTuple, SwapExecutedEvent.OutputTuple, SwapExecutedEvent.OutputObject>;
    getEvent(key: 'SwapRateUpdated'): TypedContractEvent<SwapRateUpdatedEvent.InputTuple, SwapRateUpdatedEvent.OutputTuple, SwapRateUpdatedEvent.OutputObject>;
    getEvent(key: 'TransferRedeemed'): TypedContractEvent<TransferRedeemedEvent.InputTuple, TransferRedeemedEvent.OutputTuple, TransferRedeemedEvent.OutputObject>;
    filters: {
        'FeeRecipientUpdated(address,address)': TypedContractEvent<FeeRecipientUpdatedEvent.InputTuple, FeeRecipientUpdatedEvent.OutputTuple, FeeRecipientUpdatedEvent.OutputObject>;
        FeeRecipientUpdated: TypedContractEvent<FeeRecipientUpdatedEvent.InputTuple, FeeRecipientUpdatedEvent.OutputTuple, FeeRecipientUpdatedEvent.OutputObject>;
        'OwnershipTransfered(address,address)': TypedContractEvent<OwnershipTransferedEvent.InputTuple, OwnershipTransferedEvent.OutputTuple, OwnershipTransferedEvent.OutputObject>;
        OwnershipTransfered: TypedContractEvent<OwnershipTransferedEvent.InputTuple, OwnershipTransferedEvent.OutputTuple, OwnershipTransferedEvent.OutputObject>;
        'SwapExecuted(address,address,address,uint256,uint256)': TypedContractEvent<SwapExecutedEvent.InputTuple, SwapExecutedEvent.OutputTuple, SwapExecutedEvent.OutputObject>;
        SwapExecuted: TypedContractEvent<SwapExecutedEvent.InputTuple, SwapExecutedEvent.OutputTuple, SwapExecutedEvent.OutputObject>;
        'SwapRateUpdated(tuple[])': TypedContractEvent<SwapRateUpdatedEvent.InputTuple, SwapRateUpdatedEvent.OutputTuple, SwapRateUpdatedEvent.OutputObject>;
        SwapRateUpdated: TypedContractEvent<SwapRateUpdatedEvent.InputTuple, SwapRateUpdatedEvent.OutputTuple, SwapRateUpdatedEvent.OutputObject>;
        'TransferRedeemed(uint16,bytes32,uint64)': TypedContractEvent<TransferRedeemedEvent.InputTuple, TransferRedeemedEvent.OutputTuple, TransferRedeemedEvent.OutputObject>;
        TransferRedeemed: TypedContractEvent<TransferRedeemedEvent.InputTuple, TransferRedeemedEvent.OutputTuple, TransferRedeemedEvent.OutputObject>;
    };
}
