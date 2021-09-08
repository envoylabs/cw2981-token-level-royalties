![Build and Test](https://github.com/envoylabs/cw2981-token-level-royalties/actions/workflows/build_and_test.yml/badge.svg)

# CW2981 Token-level Royalties

An example of porting EIP2981 to implement royalties at a per-contract level.

Exposes two new query message types:

```rust
// Should be called on sale to see if royalties are owed
// by the marketplace selling the NFT.
// See https://eips.ethereum.org/EIPS/eip-2981
RoyaltyInfo {
    token_id: String,
    // the denom of this sale must also be the denom returned by RoyaltiesInfoResponse
    sale_price: Coin,
},

// Called against the token_id and contract to determine if this NFT
// implements royalties
CheckRoyalties {
    token_id: String,
},
```

Note that unlike the contract-wide example, `CheckRoyalties` takes an argument, in this case, the `token_id` of the NFT. It will return a boolean to indicate if that NFT was minted with royalty metadata attached.
