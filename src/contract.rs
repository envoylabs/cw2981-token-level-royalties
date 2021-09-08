#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    coin, to_binary, Binary, BlockInfo, Coin, Deps, DepsMut, Env, MessageInfo, Order, Pair,
    Response, StdError, StdResult,
};

use cw0::maybe_addr;
use cw2::set_contract_version;
use cw721::{
    AllNftInfoResponse, ApprovedForAllResponse, ContractInfoResponse, Expiration, NftInfoResponse,
    NumTokensResponse, OwnerOfResponse, TokensResponse,
};

use cw721_base::contract::{
    execute_approve, execute_approve_all, execute_revoke, execute_revoke_all, execute_send_nft,
    execute_transfer_nft,
};
use cw721_base::msg::{InstantiateMsg, MinterResponse};
use cw721_base::state::{
    increment_tokens, num_tokens, tokens, Approval, TokenInfo, MINTER, OPERATORS,
};

use crate::msg::{CheckRoyaltiesResponse, ExecuteMsg, MintMsg, QueryMsg, RoyaltiesInfoResponse};
use crate::state::{RoyaltiesInfo, CONTRACT_INFO, ROYALTIES_INFO};
use cw_storage_plus::Bound;

use percentage::Percentage;

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:cw2981-token-level-royalties";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let info = ContractInfoResponse {
        name: msg.name,
        symbol: msg.symbol,
    };
    CONTRACT_INFO.save(deps.storage, &info)?;

    let minter = deps.api.addr_validate(&msg.minter)?;
    MINTER.save(deps.storage, &minter)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, cw721_base::ContractError> {
    match msg {
        ExecuteMsg::Mint(msg) => execute_mint(deps, env, info, msg),
        ExecuteMsg::Approve {
            spender,
            token_id,
            expires,
        } => execute_approve(deps, env, info, spender, token_id, expires),
        ExecuteMsg::Revoke { spender, token_id } => {
            execute_revoke(deps, env, info, spender, token_id)
        }
        ExecuteMsg::ApproveAll { operator, expires } => {
            execute_approve_all(deps, env, info, operator, expires)
        }
        ExecuteMsg::RevokeAll { operator } => execute_revoke_all(deps, env, info, operator),
        ExecuteMsg::TransferNft {
            recipient,
            token_id,
        } => execute_transfer_nft(deps, env, info, recipient, token_id),
        ExecuteMsg::SendNft {
            contract,
            token_id,
            msg,
        } => execute_send_nft(deps, env, info, contract, token_id, msg),
    }
}

pub fn execute_mint(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: MintMsg,
) -> Result<Response, cw721_base::ContractError> {
    let minter = MINTER.load(deps.storage)?;

    if info.sender != minter {
        return Err(cw721_base::ContractError::Unauthorized {});
    }

    // create the token
    let token = TokenInfo {
        owner: deps.api.addr_validate(&msg.owner)?,
        approvals: vec![],
        name: msg.name,
        description: msg.description.unwrap_or_default(),
        image: msg.image,
    };
    tokens().update(deps.storage, &msg.token_id, |old| match old {
        Some(_) => Err(cw721_base::ContractError::Claimed {}),
        None => Ok(token),
    })?;
    increment_tokens(deps.storage)?;

    // create the royalties lookup
    let payment_address = match msg.royalty_payment_address {
        Some(addr) => Some(deps.api.addr_validate(&addr)?),
        None => None,
    };
    let royalties_info = RoyaltiesInfo {
        royalty_payments: msg.royalty_payments,
        royalty_percentage: msg.royalty_percentage,
        royalty_payment_address: payment_address,
    };
    ROYALTIES_INFO.update(deps.storage, &msg.token_id, |_| -> StdResult<_> {
        Ok(royalties_info)
    })?;

    Ok(Response::new()
        .add_attribute("action", "mint")
        .add_attribute("minter", info.sender)
        .add_attribute("token_id", msg.token_id))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::RoyaltyInfo {
            token_id,
            sale_price,
        } => to_binary(&query_royalties_info(deps, token_id, sale_price)?),
        QueryMsg::CheckRoyalties { token_id } => to_binary(&check_royalties(deps, token_id)?),
        QueryMsg::Minter {} => to_binary(&query_minter(deps)?),
        QueryMsg::ContractInfo {} => to_binary(&query_contract_info(deps)?),
        QueryMsg::NftInfo { token_id } => to_binary(&query_nft_info(deps, token_id)?),
        QueryMsg::OwnerOf {
            token_id,
            include_expired,
        } => to_binary(&query_owner_of(
            deps,
            env,
            token_id,
            include_expired.unwrap_or(false),
        )?),
        QueryMsg::AllNftInfo {
            token_id,
            include_expired,
        } => to_binary(&query_all_nft_info(
            deps,
            env,
            token_id,
            include_expired.unwrap_or(false),
        )?),
        QueryMsg::ApprovedForAll {
            owner,
            include_expired,
            start_after,
            limit,
        } => to_binary(&query_all_approvals(
            deps,
            env,
            owner,
            include_expired.unwrap_or(false),
            start_after,
            limit,
        )?),
        QueryMsg::NumTokens {} => to_binary(&query_num_tokens(deps)?),
        QueryMsg::Tokens {
            owner,
            start_after,
            limit,
        } => to_binary(&query_tokens(deps, owner, start_after, limit)?),
        QueryMsg::AllTokens { start_after, limit } => {
            to_binary(&query_all_tokens(deps, start_after, limit)?)
        }
    }
}

// NOTE: default behaviour here is to round down
// EIP2981 specifies that the rounding behaviour is at the discretion of the implementer
pub fn query_royalties_info(
    deps: Deps,
    token_id: String,
    sale_price: Coin,
) -> StdResult<RoyaltiesInfoResponse> {
    let royalties_info = ROYALTIES_INFO.may_load(deps.storage, &token_id)?.unwrap();
    let royalty_percentage = match royalties_info.royalty_percentage {
        Some(pct) => Percentage::from(pct),
        None => Percentage::from(0),
    };
    let royalty_from_sale_price = royalty_percentage.apply_to(sale_price.amount.u128());

    let royalty_address = match royalties_info.royalty_payment_address {
        Some(addr) => addr.to_string(),
        None => String::from(""),
    };
    Ok(RoyaltiesInfoResponse {
        address: royalty_address,
        royalty_amount: coin(royalty_from_sale_price, sale_price.denom),
    })
}

pub fn check_royalties(deps: Deps, token_id: String) -> StdResult<CheckRoyaltiesResponse> {
    let royalties_info = ROYALTIES_INFO.may_load(deps.storage, &token_id)?.unwrap();
    Ok(CheckRoyaltiesResponse {
        royalty_payments: royalties_info.royalty_payments,
    })
}

pub fn query_minter(deps: Deps) -> StdResult<MinterResponse> {
    let minter_addr = MINTER.load(deps.storage)?;
    Ok(MinterResponse {
        minter: minter_addr.to_string(),
    })
}

pub fn query_contract_info(deps: Deps) -> StdResult<ContractInfoResponse> {
    CONTRACT_INFO.load(deps.storage)
}

pub fn query_num_tokens(deps: Deps) -> StdResult<NumTokensResponse> {
    let count = num_tokens(deps.storage)?;
    Ok(NumTokensResponse { count })
}

pub fn query_nft_info(deps: Deps, token_id: String) -> StdResult<NftInfoResponse> {
    let info = tokens().load(deps.storage, &token_id)?;
    Ok(NftInfoResponse {
        name: info.name,
        description: info.description,
        image: info.image,
    })
}

pub fn query_owner_of(
    deps: Deps,
    env: Env,
    token_id: String,
    include_expired: bool,
) -> StdResult<OwnerOfResponse> {
    let info = tokens().load(deps.storage, &token_id)?;
    Ok(OwnerOfResponse {
        owner: info.owner.to_string(),
        approvals: humanize_approvals(&env.block, &info, include_expired),
    })
}

const DEFAULT_LIMIT: u32 = 10;
const MAX_LIMIT: u32 = 30;

pub fn query_all_approvals(
    deps: Deps,
    env: Env,
    owner: String,
    include_expired: bool,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<ApprovedForAllResponse> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_addr = maybe_addr(deps.api, start_after)?;
    let start = start_addr.map(|addr| Bound::exclusive(addr.as_ref()));

    let owner_addr = deps.api.addr_validate(&owner)?;
    let res: StdResult<Vec<_>> = OPERATORS
        .prefix(&owner_addr)
        .range(deps.storage, start, None, Order::Ascending)
        .filter(|r| include_expired || r.is_err() || !r.as_ref().unwrap().1.is_expired(&env.block))
        .take(limit)
        .map(parse_approval)
        .collect();
    Ok(ApprovedForAllResponse { operators: res? })
}

fn parse_approval(item: StdResult<Pair<Expiration>>) -> StdResult<cw721::Approval> {
    item.and_then(|(k, expires)| {
        let spender = String::from_utf8(k)?;
        Ok(cw721::Approval { spender, expires })
    })
}

pub fn query_tokens(
    deps: Deps,
    owner: String,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<TokensResponse> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start = start_after.map(Bound::exclusive);

    let owner_addr = deps.api.addr_validate(&owner)?;
    let pks: Vec<_> = tokens()
        .idx
        .owner
        .prefix(owner_addr)
        .keys(deps.storage, start, None, Order::Ascending)
        .take(limit)
        .collect();

    let res: Result<Vec<_>, _> = pks.iter().map(|v| String::from_utf8(v.to_vec())).collect();
    let tokens = res.map_err(StdError::invalid_utf8)?;
    Ok(TokensResponse { tokens })
}

pub fn query_all_tokens(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<TokensResponse> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_addr = maybe_addr(deps.api, start_after)?;
    let start = start_addr.map(|addr| Bound::exclusive(addr.as_ref()));

    let tokens: StdResult<Vec<String>> = tokens()
        .range(deps.storage, start, None, Order::Ascending)
        .take(limit)
        .map(|item| item.map(|(k, _)| String::from_utf8_lossy(&k).to_string()))
        .collect();
    Ok(TokensResponse { tokens: tokens? })
}

pub fn query_all_nft_info(
    deps: Deps,
    env: Env,
    token_id: String,
    include_expired: bool,
) -> StdResult<AllNftInfoResponse> {
    let info = tokens().load(deps.storage, &token_id)?;
    Ok(AllNftInfoResponse {
        access: OwnerOfResponse {
            owner: info.owner.to_string(),
            approvals: humanize_approvals(&env.block, &info, include_expired),
        },
        info: NftInfoResponse {
            name: info.name,
            description: info.description,
            image: info.image,
        },
    })
}

fn humanize_approvals(
    block: &BlockInfo,
    info: &TokenInfo,
    include_expired: bool,
) -> Vec<cw721::Approval> {
    info.approvals
        .iter()
        .filter(|apr| include_expired || !apr.is_expired(block))
        .map(humanize_approval)
        .collect()
}

fn humanize_approval(approval: &Approval) -> cw721::Approval {
    cw721::Approval {
        spender: approval.spender.to_string(),
        expires: approval.expires,
    }
}

#[cfg(test)]
mod tests {
    use crate::msg::MintMsg;
    use crate::ContractError;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_binary, CosmosMsg, Uint128, WasmMsg};
    use cw721::Cw721ReceiveMsg;

    use super::*;
    use cw721::ApprovedForAllResponse;

    const MINTER: &str = "merlin";
    const CONTRACT_NAME: &str = "Magic Power";
    const SYMBOL: &str = "MGK";

    fn setup_contract(deps: DepsMut) {
        let msg = InstantiateMsg {
            name: CONTRACT_NAME.to_string(),
            symbol: SYMBOL.to_string(),
            minter: String::from(MINTER),
        };
        let info = mock_info("creator", &[]);
        let res = instantiate(deps, mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn proper_instantiation() {
        let mut deps = mock_dependencies(&[]);

        let msg = InstantiateMsg {
            name: CONTRACT_NAME.to_string(),
            symbol: SYMBOL.to_string(),
            minter: String::from(MINTER),
        };
        let info = mock_info("creator", &[]);

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query_minter(deps.as_ref()).unwrap();
        assert_eq!(MINTER, res.minter);
        let info = query_contract_info(deps.as_ref()).unwrap();
        assert_eq!(
            info,
            ContractInfoResponse {
                name: CONTRACT_NAME.to_string(),
                symbol: SYMBOL.to_string(),
            }
        );

        let count = query_num_tokens(deps.as_ref()).unwrap();
        assert_eq!(0, count.count);

        // list the token_ids
        let tokens = query_all_tokens(deps.as_ref(), None, None).unwrap();
        assert_eq!(0, tokens.tokens.len());
    }

    #[test]
    fn minting() {
        let mut deps = mock_dependencies(&[]);
        setup_contract(deps.as_mut());

        let token_id = "petrify".to_string();
        let name = "Petrify with Gaze".to_string();
        let description = "Allows the owner to petrify anyone looking at him or her".to_string();

        let mint_msg = ExecuteMsg::Mint(MintMsg {
            token_id: token_id.clone(),
            owner: String::from("medusa"),
            name: name.clone(),
            description: Some(description.clone()),
            image: None,
            royalty_payments: true,
            royalty_percentage: Some(10),
            royalty_payment_address: Some(String::from(MINTER)),
        });

        // random cannot mint
        let random = mock_info("random", &[]);
        let err = execute(deps.as_mut(), mock_env(), random, mint_msg.clone()).unwrap_err();
        assert_eq!(ContractError::from(err), ContractError::Unauthorized {});

        // minter can mint
        let allowed = mock_info(MINTER, &[]);
        let _ = execute(deps.as_mut(), mock_env(), allowed, mint_msg).unwrap();

        // ensure num tokens increases
        let count = query_num_tokens(deps.as_ref()).unwrap();
        assert_eq!(1, count.count);

        // unknown nft returns error
        let _ = query_nft_info(deps.as_ref(), "unknown".to_string()).unwrap_err();

        // this nft info is correct
        let info = query_nft_info(deps.as_ref(), token_id.clone()).unwrap();
        assert_eq!(
            info,
            NftInfoResponse {
                name,
                description,
                image: None,
            }
        );

        // owner info is correct
        let owner = query_owner_of(deps.as_ref(), mock_env(), token_id.clone(), true).unwrap();
        assert_eq!(
            owner,
            OwnerOfResponse {
                owner: String::from("medusa"),
                approvals: vec![],
            }
        );

        // royalties info is correct in case it was sold for 1_000_000 right away
        let queried_royalties_info = query_royalties_info(
            deps.as_ref(),
            token_id.clone(),
            coin(Uint128::new(1_000_000).u128(), "ujuno"),
        )
        .unwrap();
        assert_eq!(
            queried_royalties_info,
            RoyaltiesInfoResponse {
                address: String::from(MINTER),
                royalty_amount: coin(Uint128::new(100_000).u128(), "ujuno")
            }
        );

        // Cannot mint same token_id again
        let mint_msg2 = ExecuteMsg::Mint(MintMsg {
            token_id: token_id.clone(),
            owner: String::from("hercules"),
            name: "copy cat".into(),
            description: None,
            image: None,
            royalty_payments: true,
            royalty_percentage: Some(10),
            royalty_payment_address: Some(String::from(MINTER)),
        });

        let allowed = mock_info(MINTER, &[]);
        let err = execute(deps.as_mut(), mock_env(), allowed, mint_msg2).unwrap_err();
        assert_eq!(ContractError::from(err), ContractError::Claimed {});

        // list the token_ids
        let tokens = query_all_tokens(deps.as_ref(), None, None).unwrap();
        assert_eq!(1, tokens.tokens.len());
        assert_eq!(vec![token_id], tokens.tokens);
    }

    #[test]
    fn transferring_nft() {
        let mut deps = mock_dependencies(&[]);
        setup_contract(deps.as_mut());

        // Mint a token
        let token_id = "melt".to_string();
        let name = "Melting power".to_string();
        let description = "Allows the owner to melt anyone looking at him or her".to_string();

        let mint_msg = ExecuteMsg::Mint(MintMsg {
            token_id: token_id.clone(),
            owner: String::from("venus"),
            name,
            description: Some(description),
            image: None,
            royalty_payments: true,
            royalty_percentage: Some(7),
            royalty_payment_address: Some(String::from(MINTER)),
        });

        let minter = mock_info(MINTER, &[]);
        execute(deps.as_mut(), mock_env(), minter, mint_msg).unwrap();

        // random cannot transfer
        let random = mock_info("random", &[]);
        let transfer_msg = ExecuteMsg::TransferNft {
            recipient: String::from("random"),
            token_id: token_id.clone(),
        };

        let err = execute(deps.as_mut(), mock_env(), random, transfer_msg).unwrap_err();
        assert_eq!(ContractError::from(err), ContractError::Unauthorized {});

        // owner can
        let random = mock_info("venus", &[]);
        let transfer_msg = ExecuteMsg::TransferNft {
            recipient: String::from("random"),
            token_id: token_id.clone(),
        };

        // check royalties info is correct at point of simulated sale
        // note also this results in 92492.54
        // so this test also documents that the behaviour is to round down
        let queried_royalties_info = query_royalties_info(
            deps.as_ref(),
            token_id.clone(),
            coin(Uint128::new(1_321_322).u128(), "ujuno"),
        )
        .unwrap();
        assert_eq!(
            queried_royalties_info,
            RoyaltiesInfoResponse {
                address: String::from(MINTER),
                royalty_amount: coin(Uint128::new(92_492).u128(), "ujuno")
            }
        );

        let res = execute(deps.as_mut(), mock_env(), random, transfer_msg).unwrap();

        assert_eq!(
            res,
            Response::new()
                .add_attribute("action", "transfer_nft")
                .add_attribute("sender", "venus")
                .add_attribute("recipient", "random")
                .add_attribute("token_id", token_id)
        );
    }

    #[test]
    fn sending_nft() {
        let mut deps = mock_dependencies(&[]);
        setup_contract(deps.as_mut());

        // Mint a token
        let token_id = "melt".to_string();
        let name = "Melting power".to_string();
        let description = "Allows the owner to melt anyone looking at him or her".to_string();

        let mint_msg = ExecuteMsg::Mint(MintMsg {
            token_id: token_id.clone(),
            owner: String::from("venus"),
            name,
            description: Some(description),
            image: None,
            royalty_payments: true,
            royalty_percentage: Some(7),
            royalty_payment_address: Some(String::from(MINTER)),
        });

        let minter = mock_info(MINTER, &[]);
        execute(deps.as_mut(), mock_env(), minter, mint_msg).unwrap();

        let msg = to_binary("You now have the melting power").unwrap();
        let target = String::from("another_contract");
        let send_msg = ExecuteMsg::SendNft {
            contract: target.clone(),
            token_id: token_id.clone(),
            msg: msg.clone(),
        };

        let random = mock_info("random", &[]);
        let err = execute(deps.as_mut(), mock_env(), random, send_msg.clone()).unwrap_err();
        assert_eq!(ContractError::from(err), ContractError::Unauthorized {});

        // but owner can
        let random = mock_info("venus", &[]);
        let res = execute(deps.as_mut(), mock_env(), random, send_msg).unwrap();

        // check royalties info is correct at point of hypothetical sale
        let queried_royalties_info = query_royalties_info(
            deps.as_ref(),
            token_id.clone(),
            coin(Uint128::new(1_321_321).u128(), "ujuno"),
        )
        .unwrap();
        assert_eq!(
            queried_royalties_info,
            RoyaltiesInfoResponse {
                address: String::from(MINTER),
                royalty_amount: coin(Uint128::new(92_492).u128(), "ujuno")
            }
        );

        let payload = Cw721ReceiveMsg {
            sender: String::from("venus"),
            token_id: token_id.clone(),
            msg,
        };
        let expected = payload.into_cosmos_msg(target.clone()).unwrap();
        // ensure expected serializes as we think it should
        match &expected {
            CosmosMsg::Wasm(WasmMsg::Execute { contract_addr, .. }) => {
                assert_eq!(contract_addr, &target)
            }
            m => panic!("Unexpected message type: {:?}", m),
        }
        // and make sure this is the request sent by the contract
        assert_eq!(
            res,
            Response::new()
                .add_message(expected)
                .add_attribute("action", "send_nft")
                .add_attribute("sender", "venus")
                .add_attribute("recipient", "another_contract")
                .add_attribute("token_id", token_id)
        );
    }

    #[test]
    fn approving_revoking() {
        let mut deps = mock_dependencies(&[]);
        setup_contract(deps.as_mut());

        // Mint a token
        let token_id = "grow".to_string();
        let name = "Growing power".to_string();
        let description = "Allows the owner to grow anything".to_string();

        let mint_msg = ExecuteMsg::Mint(MintMsg {
            token_id: token_id.clone(),
            owner: String::from("demeter"),
            name,
            description: Some(description),
            image: None,
            royalty_payments: false,
            royalty_percentage: None,
            royalty_payment_address: None,
        });

        let minter = mock_info(MINTER, &[]);
        execute(deps.as_mut(), mock_env(), minter, mint_msg).unwrap();

        // Give random transferring power
        let approve_msg = ExecuteMsg::Approve {
            spender: String::from("random"),
            token_id: token_id.clone(),
            expires: None,
        };
        let owner = mock_info("demeter", &[]);
        let res = execute(deps.as_mut(), mock_env(), owner, approve_msg).unwrap();
        assert_eq!(
            res,
            Response::new()
                .add_attribute("action", "approve")
                .add_attribute("sender", "demeter")
                .add_attribute("spender", "random")
                .add_attribute("token_id", token_id.clone())
        );

        // random can now transfer
        let random = mock_info("random", &[]);
        let transfer_msg = ExecuteMsg::TransferNft {
            recipient: String::from("person"),
            token_id: token_id.clone(),
        };
        execute(deps.as_mut(), mock_env(), random, transfer_msg).unwrap();

        // Approvals are removed / cleared
        let query_msg = QueryMsg::OwnerOf {
            token_id: token_id.clone(),
            include_expired: None,
        };
        let res: OwnerOfResponse =
            from_binary(&query(deps.as_ref(), mock_env(), query_msg.clone()).unwrap()).unwrap();
        assert_eq!(
            res,
            OwnerOfResponse {
                owner: String::from("person"),
                approvals: vec![],
            }
        );

        // Approve, revoke, and check for empty, to test revoke
        let approve_msg = ExecuteMsg::Approve {
            spender: String::from("random"),
            token_id: token_id.clone(),
            expires: None,
        };
        let owner = mock_info("person", &[]);
        execute(deps.as_mut(), mock_env(), owner.clone(), approve_msg).unwrap();

        let revoke_msg = ExecuteMsg::Revoke {
            spender: String::from("random"),
            token_id,
        };
        execute(deps.as_mut(), mock_env(), owner, revoke_msg).unwrap();

        // Approvals are now removed / cleared
        let res: OwnerOfResponse =
            from_binary(&query(deps.as_ref(), mock_env(), query_msg).unwrap()).unwrap();
        assert_eq!(
            res,
            OwnerOfResponse {
                owner: String::from("person"),
                approvals: vec![],
            }
        );
    }

    #[test]
    fn approving_all_revoking_all() {
        let mut deps = mock_dependencies(&[]);
        setup_contract(deps.as_mut());

        // Mint a couple tokens (from the same owner)
        let token_id1 = "grow1".to_string();
        let name1 = "Growing power".to_string();
        let description1 = "Allows the owner the power to grow anything".to_string();
        let token_id2 = "grow2".to_string();
        let name2 = "More growing power".to_string();
        let description2 = "Allows the owner the power to grow anything even faster".to_string();

        let mint_msg1 = ExecuteMsg::Mint(MintMsg {
            token_id: token_id1.clone(),
            owner: String::from("demeter"),
            name: name1,
            description: Some(description1),
            image: None,
            royalty_payments: false,
            royalty_percentage: None,
            royalty_payment_address: None,
        });

        let minter = mock_info(MINTER, &[]);
        execute(deps.as_mut(), mock_env(), minter.clone(), mint_msg1).unwrap();

        let mint_msg2 = ExecuteMsg::Mint(MintMsg {
            token_id: token_id2.clone(),
            owner: String::from("demeter"),
            name: name2,
            description: Some(description2),
            image: None,
            royalty_payments: false,
            royalty_percentage: None,
            royalty_payment_address: None,
        });

        execute(deps.as_mut(), mock_env(), minter, mint_msg2).unwrap();

        // paginate the token_ids
        let tokens = query_all_tokens(deps.as_ref(), None, Some(1)).unwrap();
        assert_eq!(1, tokens.tokens.len());
        assert_eq!(vec![token_id1.clone()], tokens.tokens);
        let tokens = query_all_tokens(deps.as_ref(), Some(token_id1.clone()), Some(3)).unwrap();
        assert_eq!(1, tokens.tokens.len());
        assert_eq!(vec![token_id2.clone()], tokens.tokens);

        // demeter gives random full (operator) power over her tokens
        let approve_all_msg = ExecuteMsg::ApproveAll {
            operator: String::from("random"),
            expires: None,
        };
        let owner = mock_info("demeter", &[]);
        let res = execute(deps.as_mut(), mock_env(), owner, approve_all_msg).unwrap();
        assert_eq!(
            res,
            Response::new()
                .add_attribute("action", "approve_all")
                .add_attribute("sender", "demeter")
                .add_attribute("operator", "random")
        );

        // random can now transfer
        let random = mock_info("random", &[]);
        let transfer_msg = ExecuteMsg::TransferNft {
            recipient: String::from("person"),
            token_id: token_id1,
        };
        execute(deps.as_mut(), mock_env(), random.clone(), transfer_msg).unwrap();

        // random can now send
        let inner_msg = WasmMsg::Execute {
            contract_addr: "another_contract".into(),
            msg: to_binary("You now also have the growing power").unwrap(),
            funds: vec![],
        };
        let msg: CosmosMsg = CosmosMsg::Wasm(inner_msg);

        let send_msg = ExecuteMsg::SendNft {
            contract: String::from("another_contract"),
            token_id: token_id2,
            msg: to_binary(&msg).unwrap(),
        };
        execute(deps.as_mut(), mock_env(), random, send_msg).unwrap();

        // Approve_all, revoke_all, and check for empty, to test revoke_all
        let approve_all_msg = ExecuteMsg::ApproveAll {
            operator: String::from("operator"),
            expires: None,
        };
        // person is now the owner of the tokens
        let owner = mock_info("person", &[]);
        execute(deps.as_mut(), mock_env(), owner, approve_all_msg).unwrap();

        let res = query_all_approvals(
            deps.as_ref(),
            mock_env(),
            String::from("person"),
            true,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            res,
            ApprovedForAllResponse {
                operators: vec![cw721::Approval {
                    spender: String::from("operator"),
                    expires: Expiration::Never {}
                }]
            }
        );

        // second approval
        let buddy_expires = Expiration::AtHeight(1234567);
        let approve_all_msg = ExecuteMsg::ApproveAll {
            operator: String::from("buddy"),
            expires: Some(buddy_expires),
        };
        let owner = mock_info("person", &[]);
        execute(deps.as_mut(), mock_env(), owner.clone(), approve_all_msg).unwrap();

        // and paginate queries
        let res = query_all_approvals(
            deps.as_ref(),
            mock_env(),
            String::from("person"),
            true,
            None,
            Some(1),
        )
        .unwrap();
        assert_eq!(
            res,
            ApprovedForAllResponse {
                operators: vec![cw721::Approval {
                    spender: String::from("buddy"),
                    expires: buddy_expires,
                }]
            }
        );
        let res = query_all_approvals(
            deps.as_ref(),
            mock_env(),
            String::from("person"),
            true,
            Some(String::from("buddy")),
            Some(2),
        )
        .unwrap();
        assert_eq!(
            res,
            ApprovedForAllResponse {
                operators: vec![cw721::Approval {
                    spender: String::from("operator"),
                    expires: Expiration::Never {}
                }]
            }
        );

        let revoke_all_msg = ExecuteMsg::RevokeAll {
            operator: String::from("operator"),
        };
        execute(deps.as_mut(), mock_env(), owner, revoke_all_msg).unwrap();

        // Approvals are removed / cleared without affecting others
        let res = query_all_approvals(
            deps.as_ref(),
            mock_env(),
            String::from("person"),
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            res,
            ApprovedForAllResponse {
                operators: vec![cw721::Approval {
                    spender: String::from("buddy"),
                    expires: buddy_expires,
                }]
            }
        );

        // ensure the filter works (nothing should be here
        let mut late_env = mock_env();
        late_env.block.height = 1234568; //expired
        let res = query_all_approvals(
            deps.as_ref(),
            late_env,
            String::from("person"),
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(0, res.operators.len());
    }

    #[test]
    fn query_tokens_by_owner() {
        let mut deps = mock_dependencies(&[]);
        setup_contract(deps.as_mut());
        let minter = mock_info(MINTER, &[]);

        // Mint a couple tokens (from the same owner)
        let token_id1 = "grow1".to_string();
        let demeter = String::from("Demeter");
        let token_id2 = "grow2".to_string();
        let ceres = String::from("Ceres");
        let token_id3 = "sing".to_string();

        let mint_msg = ExecuteMsg::Mint(MintMsg {
            token_id: token_id1.clone(),
            owner: demeter.clone(),
            name: "Growing power".to_string(),
            description: Some("Allows the owner the power to grow anything".to_string()),
            image: None,
            royalty_payments: false,
            royalty_percentage: None,
            royalty_payment_address: None,
        });
        execute(deps.as_mut(), mock_env(), minter.clone(), mint_msg).unwrap();

        // sense check a hypothetical sale
        let queried_royalties_info = query_royalties_info(
            deps.as_ref(),
            token_id1.clone(),
            coin(Uint128::new(1_000_000).u128(), "ujuno"),
        )
        .unwrap();
        assert_eq!(
            queried_royalties_info,
            RoyaltiesInfoResponse {
                address: String::from(""),
                royalty_amount: coin(Uint128::new(0).u128(), "ujuno")
            }
        );

        let mint_msg = ExecuteMsg::Mint(MintMsg {
            token_id: token_id2.clone(),
            owner: ceres.clone(),
            name: "More growing power".to_string(),
            description: Some(
                "Allows the owner the power to grow anything even faster".to_string(),
            ),
            image: None,
            royalty_payments: false,
            royalty_percentage: None,
            royalty_payment_address: None,
        });
        execute(deps.as_mut(), mock_env(), minter.clone(), mint_msg).unwrap();

        let mint_msg = ExecuteMsg::Mint(MintMsg {
            token_id: token_id3.clone(),
            owner: demeter.clone(),
            name: "Sing a lullaby".to_string(),
            description: Some("Calm even the most excited children".to_string()),
            image: None,
            royalty_payments: false,
            royalty_percentage: None,
            royalty_payment_address: None,
        });
        execute(deps.as_mut(), mock_env(), minter, mint_msg).unwrap();

        // get all tokens in order:
        let expected = vec![token_id1.clone(), token_id2.clone(), token_id3.clone()];
        let tokens = query_all_tokens(deps.as_ref(), None, None).unwrap();
        assert_eq!(&expected, &tokens.tokens);
        // paginate
        let tokens = query_all_tokens(deps.as_ref(), None, Some(2)).unwrap();
        assert_eq!(&expected[..2], &tokens.tokens[..]);
        let tokens = query_all_tokens(deps.as_ref(), Some(expected[1].clone()), None).unwrap();
        assert_eq!(&expected[2..], &tokens.tokens[..]);

        // get by owner
        let by_ceres = vec![token_id2];
        let by_demeter = vec![token_id1, token_id3];
        // all tokens by owner
        let tokens = query_tokens(deps.as_ref(), demeter.clone(), None, None).unwrap();
        assert_eq!(&by_demeter, &tokens.tokens);
        let tokens = query_tokens(deps.as_ref(), ceres, None, None).unwrap();
        assert_eq!(&by_ceres, &tokens.tokens);

        // paginate for demeter
        let tokens = query_tokens(deps.as_ref(), demeter.clone(), None, Some(1)).unwrap();
        assert_eq!(&by_demeter[..1], &tokens.tokens[..]);
        let tokens =
            query_tokens(deps.as_ref(), demeter, Some(by_demeter[0].clone()), Some(3)).unwrap();
        assert_eq!(&by_demeter[1..], &tokens.tokens[..]);
    }
}
