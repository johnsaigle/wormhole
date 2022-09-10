module token_bridge::transfer_tokens {
    use aptos_framework::aptos_coin::{AptosCoin};
    use aptos_framework::bcs::to_bytes;
    use aptos_framework::coin::{Self, Coin};

    use wormhole::u16::{Self, U16};
    use wormhole::u256;

    use token_bridge::bridge_state as state;
    use token_bridge::transfer;
    use token_bridge::transfer_result::{Self, TransferResult};
    use token_bridge::transfer_with_payload;
    use token_bridge::utils;
    use token_bridge::wrapped;

    const E_TOO_MUCH_RELAYER_FEE: u64 = 0;

    public entry fun transfer_tokens_with_signer<CoinType>(
        sender: &signer,
        amount: u64,
        recipient_chain: u64,
        recipient: vector<u8>,
        relayer_fee: u64,
        wormhole_fee: u64,
        nonce: u64
        ): u64 {
        let coins = coin::withdraw<CoinType>(sender, amount);
        //let relayer_fee_coins = coin::withdraw<AptosCoin>(sender, relayer_fee);
        let wormhole_fee_coins = coin::withdraw<AptosCoin>(sender, wormhole_fee);
        transfer_tokens<CoinType>(coins, wormhole_fee_coins, u16::from_u64(recipient_chain), recipient, relayer_fee, nonce)
    }

    public fun transfer_tokens<CoinType>(
        coins: Coin<CoinType>,
        wormhole_fee_coins: Coin<AptosCoin>,
        recipient_chain: U16,
        recipient: vector<u8>,
        relayer_fee: u64,
        nonce: u64
        ): u64 {
        let result = transfer_tokens_internal<CoinType>(coins, relayer_fee);
        let (token_chain, token_address, normalized_amount, normalized_relayer_fee)
            = transfer_result::destroy(result);
        let transfer = transfer::create(
            normalized_amount,
            token_address,
            token_chain,
            recipient,
            recipient_chain,
            normalized_relayer_fee,
        );
        state::publish_message(
            nonce,
            transfer::encode(transfer),
            wormhole_fee_coins,
        )
    }

    public fun transfer_tokens_with_payload_with_signer<CoinType>(
        sender: &signer,
        amount: u64,
        wormhole_fee: u64,
        recipient_chain: U16,
        recipient: vector<u8>,
        nonce: u64,
        payload: vector<u8>
        ): u64 {
        let coins = coin::withdraw<CoinType>(sender, amount);
        let wormhole_fee_coins = coin::withdraw<AptosCoin>(sender, wormhole_fee);
        transfer_tokens_with_payload(coins, wormhole_fee_coins, recipient_chain, recipient, nonce, payload)
    }

    public fun transfer_tokens_with_payload<CoinType>(
        coins: Coin<CoinType>,
        wormhole_fee_coins: Coin<AptosCoin>,
        recipient_chain: U16,
        recipient: vector<u8>,
        nonce: u64,
        payload: vector<u8>
        ): u64 {
        let result = transfer_tokens_internal<CoinType>(coins, 0);
        let (token_chain, token_address, normalized_amount, _)
            = transfer_result::destroy(result);
        let transfer = transfer_with_payload::create(
            normalized_amount,
            token_address,
            token_chain,
            recipient,
            recipient_chain,
            to_bytes<address>(&@token_bridge), //TODO - is token bridge the only one who will ever call log_transfer_with_payload? (no)
            payload
        );
        let payload = transfer_with_payload::encode(transfer);
        state::publish_message(
            nonce,
            payload,
            wormhole_fee_coins,
        )
    }

    #[test_only]
    public fun transfer_tokens_test<CoinType>(
        coins: Coin<CoinType>,
        relayer_fee: u64,
    ): TransferResult {
        transfer_tokens_internal(coins, relayer_fee)
    }

    // transfer a native or wraped token from sender to token_bridge
    fun transfer_tokens_internal<CoinType>(
        coins: Coin<CoinType>,
        relayer_fee: u64,
        ): TransferResult {

        // transfer coin to token_bridge
        if (!coin::is_account_registered<CoinType>(@token_bridge)){
            coin::register<CoinType>(&state::token_bridge_signer());
        };
        if (!coin::is_account_registered<AptosCoin>(@token_bridge)){
            coin::register<AptosCoin>(&state::token_bridge_signer());
        };

        let amount = coin::value<CoinType>(&coins);
        assert!(relayer_fee <= amount, E_TOO_MUCH_RELAYER_FEE);

        if (state::is_wrapped_asset<CoinType>()) {
            // now we burn the wrapped coins to remove them from circulation
            wrapped::burn<CoinType>(coins);
        } else {
            coin::deposit<CoinType>(@token_bridge, coins);
            // if we're seeing this native token for the first time, store its
            // type info
            if (!state::is_registered_native_asset<CoinType>()) {
                state::set_native_asset_type_info<CoinType>();
            };
        };

        let origin_info = state::origin_info<CoinType>();
        let token_chain = state::get_origin_info_token_chain(&origin_info);
        let token_address = state::get_origin_info_token_address(&origin_info);

        let decimals_token = coin::decimals<CoinType>();

        let normalized_amount = utils::normalize_amount(u256::from_u64(amount), decimals_token);
        let normalized_relayer_fee = utils::normalize_amount(u256::from_u64(relayer_fee), decimals_token);

        let transfer_result: TransferResult = transfer_result::create(
            token_chain,
            token_address,
            normalized_amount,
            normalized_relayer_fee,
        );
        transfer_result
    }


}

#[test_only]
module token_bridge::transfer_tokens_test {
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::string::{utf8};
    use aptos_framework::aptos_coin::{Self, AptosCoin};

    use token_bridge::token_bridge::{Self as bridge};
    use token_bridge::transfer_tokens;
    use token_bridge::wrapped;
    use token_bridge::transfer_result;
    use token_bridge::token_hash;

    use token_bridge::register_chain;

    use wrapped_coin::coin::T;

    /// Registration VAA for the etheruem token bridge 0xdeadbeef
    const ETHEREUM_TOKEN_REG: vector<u8> = x"0100000000010015d405c74be6d93c3c33ed6b48d8db70dfb31e0981f8098b2a6c7583083e0c3343d4a1abeb3fc1559674fa067b0c0e2e9de2fafeaecdfeae132de2c33c9d27cc0100000001000000010001000000000000000000000000000000000000000000000000000000000000000400000000016911ae00000000000000000000000000000000000000000000546f6b656e427269646765010000000200000000000000000000000000000000000000000000000000000000deadbeef";

    /// Attestation VAA sent from the ethereum token bridge 0xdeadbeef
    const ATTESTATION_VAA: vector<u8> = x"01000000000100102d399190fa61daccb11c2ea4f7a3db3a9365e5936bcda4cded87c1b9eeb095173514f226256d5579af71d4089eb89496befb998075ba94cd1d4460c5c57b84000000000100000001000200000000000000000000000000000000000000000000000000000000deadbeef0000000002634973000200000000000000000000000000000000000000000000000000000000beefface00020c0000000000000000000000000000000000000000000000000000000042454546000000000000000000000000000000000042656566206661636520546f6b656e";

    struct MyCoin has key {}

    fun init_my_token(admin: &signer, amount: u64): Coin<MyCoin> {
        let name = utf8(b"mycoindd");
        let symbol = utf8(b"MCdd");
        let decimals = 6;
        let monitor_supply = true;
        let (burn_cap, freeze_cap, mint_cap) = coin::initialize<MyCoin>(admin, name, symbol, decimals, monitor_supply);
        let coins = coin::mint<MyCoin>(amount, &mint_cap);
        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
        coin::destroy_freeze_cap(freeze_cap);
        coins
    }

    fun setup(
        aptos_framework: &signer,
        token_bridge: &signer,
        deployer: &signer,
    ) {
        // we initialise the bridge with zero fees to avoid having to mint fee
        // tokens in these tests. The wormolhe fee handling is already tested
        // in wormhole.move, so it's unnecessary here.
        let (burn_cap, mint_cap) = aptos_coin::initialize_for_test(aptos_framework);
        wormhole::wormhole_test::setup(0);
        bridge::init_test(deployer);

        coin::register<AptosCoin>(deployer);
        coin::register<AptosCoin>(token_bridge); //how important is this registration step and where to check it?
        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }

    // test transfer wrapped coin
    #[test(aptos_framework = @aptos_framework, token_bridge=@token_bridge, deployer=@deployer)]
    fun test_transfer_wrapped_token(aptos_framework: &signer, token_bridge: &signer, deployer: &signer) {
        setup(aptos_framework, token_bridge, deployer);
        register_chain::submit_vaa(ETHEREUM_TOKEN_REG);
        // TODO(csongor): create a better error message when attestation is missing
        let _addr = wrapped::create_wrapped_coin_type(ATTESTATION_VAA);
        // TODO(csongor): write a blurb about why this test works (something
        // something static linking)
        // initialize coin using type T, move caps to token_bridge, sets bridge state variables
        wrapped::create_wrapped_coin<T>(ATTESTATION_VAA);

        // test transfer wrapped tokens
        let beef_coins = wrapped::mint<T>(100000);
        assert!(coin::supply<T>() == std::option::some(100000), 0);
        let result = transfer_tokens::transfer_tokens_test<T>(
            beef_coins,
            2,
        );
        let (token_chain, token_address, normalized_amount, normalized_relayer_fee)
            = transfer_result::destroy(result);

        // make sure the wrapped assets have been burned
        assert!(coin::supply<T>() == std::option::some(0), 0);

        assert!(token_chain == wormhole::u16::from_u64(2), 0);
        assert!(token_address == x"00000000000000000000000000000000000000000000000000000000beefface", 0);
        // the coin has 12 decimals, so the amount gets scaled by a factor 10^-4
        // since the normalised amounts are 8 decimals
        assert!(normalized_amount == wormhole::u256::from_u64(10), 0);
        assert!(normalized_relayer_fee == wormhole::u256::from_u64(0), 0);
    }

    #[test(aptos_framework = @aptos_framework, token_bridge=@token_bridge, deployer=@deployer)]
    #[expected_failure(abort_code = 0)]
    fun test_transfer_wrapped_token_too_much_relayer_fee(
        aptos_framework: &signer,
        token_bridge: &signer,
        deployer: &signer
    ) {
        setup(aptos_framework, token_bridge, deployer);
        register_chain::submit_vaa(ETHEREUM_TOKEN_REG);
        let _addr = wrapped::create_wrapped_coin_type(ATTESTATION_VAA);
        wrapped::create_wrapped_coin<T>(ATTESTATION_VAA);

        // this will fail because the relayer fee exceeds the amount
        let beef_coins = wrapped::mint<T>(100000);
        assert!(coin::supply<T>() == std::option::some(100000), 0);
        let result = transfer_tokens::transfer_tokens_test<T>(beef_coins, 200000);
        let (_, _, _, _) = transfer_result::destroy(result);
    }

    // test transfer native coin
    #[test(aptos_framework = @aptos_framework, token_bridge=@token_bridge, deployer=@deployer)]
    fun test_transfer_native_token(aptos_framework: &signer, token_bridge: &signer, deployer: &signer) {
        setup(aptos_framework, token_bridge, deployer);

        let my_coins = init_my_token(token_bridge, 10000);

        // make sure the token bridge is not registered yet for this coin
        assert!(!coin::is_account_registered<MyCoin>(@token_bridge), 0);

        let result = transfer_tokens::transfer_tokens_test<MyCoin>(my_coins, 500);

        // the token bridge should now be registered and hold the balance
        assert!(coin::balance<MyCoin>(@token_bridge) == 10000, 0);

        let (token_chain, token_address, normalized_amount, normalized_relayer_fee)
            = transfer_result::destroy(result);

        assert!(token_chain == wormhole::state::get_chain_id(), 0);
        assert!(token_address == token_hash::get_bytes(&token_hash::derive<MyCoin>()), 0);
        // the coin has 6 decimals, so the amount doesn't get scaled
        assert!(normalized_amount == wormhole::u256::from_u64(10000), 0);
        assert!(normalized_relayer_fee == wormhole::u256::from_u64(500), 0);
    }
}
