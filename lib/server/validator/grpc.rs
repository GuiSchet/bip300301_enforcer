use bitcoin::{
    Amount, Block, BlockHash, Transaction, TxOut, absolute::Height, amount::CheckedSum,
    hashes::Hash,
};
use buffa::MessageField;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};
use futures::{StreamExt as _, stream::BoxStream};
use miette::IntoDiagnostic as _;

use crate::{
    convert,
    messages::{
        CoinbaseMessage, M1ProposeSidechain, M2AckSidechain, M3ProposeBundle, M4AckBundles,
        parse_m8_tx,
    },
    proto::{
        ToStatus as _,
        common::{ConsensusHex, Hex, ReverseHex},
        mainchain::{
            Bip300BlockDelta, Bip300CoinbaseMessage, ConfirmedBmmRequest,
            GetBip300BlockDeltaRequest, GetBip300BlockDeltaResponse, GetBlockHeaderInfoRequest,
            GetBlockHeaderInfoResponse, GetBlockInfoRequest, GetBlockInfoResponse,
            GetBmmHStarCommitmentRequest, GetBmmHStarCommitmentResponse, GetChainInfoRequest,
            GetChainInfoResponse, GetChainTipRequest, GetChainTipResponse, GetCoinbasePSBTRequest,
            GetCoinbasePSBTResponse, GetCtipRequest, GetCtipResponse, GetSidechainProposalsRequest,
            GetSidechainProposalsResponse, GetSidechainsRequest, GetSidechainsResponse,
            GetTwoWayPegDataRequest, GetTwoWayPegDataResponse, GetWithdrawalBundleProposalsRequest,
            GetWithdrawalBundleProposalsResponse, M1Delta, M2Delta, M3Delta, M4Delta, M7Delta,
            Network, StopRequest, StopResponse, SubscribeEventsRequest, SubscribeEventsResponse,
            SubscribeHeaderSyncProgressRequest, SubscribeHeaderSyncProgressResponse, TreasuryCtip,
            TreasuryTransition, bip300coinbase_message, get_block_info_response,
            get_bmm_h_star_commitment_response, get_chain_info_response::Bip300Constants,
            get_ctip_response::Ctip, get_sidechain_proposals_response::SidechainProposal,
            get_sidechains_response::SidechainInfo, get_withdrawal_bundle_proposals_response,
            m2delta, m4delta, treasury_transition,
        },
        mainchain_service::ValidatorService,
        wrap_u32,
    },
    server::{internal_err, missing_field, parse_sidechain_id, validator::Server},
    types::{
        BlockEvent, BlockInfo as ValidatorBlockInfo, Ctip as ValidatorCtip, HeaderInfo, M6id,
        SidechainNumber, Thresholds, TreasuryUtxo, WithdrawalBundleEventKind,
    },
    validator::{
        BlockAckBundleAction, BlockAckSidechainProposalEffect, BlockCoinbaseMsg, BlockDiff, BlockTx,
    },
};

const MAX_BIP300_BLOCK_DELTA_ANCESTORS: u32 = 4_095;

fn treasury_ctip(ctip: &ValidatorCtip) -> TreasuryCtip {
    TreasuryCtip {
        txid: MessageField::some(ReverseHex::encode(&ctip.outpoint.txid)),
        vout: ctip.outpoint.vout,
        value_sats: ctip.value.to_sat(),
    }
}

fn historical_treasury_ctip(treasury: &TreasuryUtxo) -> TreasuryCtip {
    TreasuryCtip {
        txid: MessageField::some(ReverseHex::encode(&treasury.outpoint.txid)),
        vout: treasury.outpoint.vout,
        value_sats: treasury.total_value.to_sat(),
    }
}

fn m4_effects(block_diff: &BlockDiff) -> Vec<m4delta::Effect> {
    let Some(acks) = block_diff.coinbase.msgs.iter().find_map(|msg| match msg {
        BlockCoinbaseMsg::AckBundles(acks) => Some(acks),
        _ => None,
    }) else {
        return Vec::new();
    };
    let mut effects = acks
        .0
        .iter()
        .map(|(sidechain_number, action)| match action {
            BlockAckBundleAction::Alarm {
                positive_votes_proposals,
            } => {
                let mut downvoted = positive_votes_proposals.iter().collect::<Vec<_>>();
                downvoted.sort_by_key(|m6id| m6id.0.to_byte_array());
                let downvoted_m6ids = downvoted
                    .into_iter()
                    .map(|m6id| ConsensusHex::encode(&m6id.0))
                    .collect();
                m4delta::Effect {
                    sidechain_number: sidechain_number.0.into(),
                    action: m4delta::effect::Action::Alarm.into(),
                    upvoted_m6id: MessageField::none(),
                    downvoted_m6ids,
                }
            }
            BlockAckBundleAction::Upvote {
                m6id,
                downvoted_others,
            } => m4delta::Effect {
                sidechain_number: sidechain_number.0.into(),
                action: m4delta::effect::Action::Upvote.into(),
                upvoted_m6id: MessageField::some(ConsensusHex::encode(&m6id.0)),
                downvoted_m6ids: downvoted_others
                    .iter()
                    .map(|m6id| ConsensusHex::encode(&m6id.0))
                    .collect(),
            },
        })
        .collect::<Vec<_>>();
    effects.sort_by_key(|effect| effect.sidechain_number);
    effects
}

fn coinbase_messages(
    block: &Block,
    block_info: &ValidatorBlockInfo,
    block_diff: &BlockDiff,
) -> Vec<Bip300CoinbaseMessage> {
    let Some(coinbase) = block.txdata.first() else {
        return Vec::new();
    };
    coinbase
        .output
        .iter()
        .enumerate()
        .filter_map(|(vout, output)| {
            let (rest, message) = CoinbaseMessage::parse(&output.script_pubkey).ok()?;
            if !rest.is_empty() {
                return None;
            }
            let (accepted, message) = match message {
                CoinbaseMessage::M1ProposeSidechain(m1) => {
                    let proposal_id = crate::types::SidechainProposalId {
                        sidechain_number: m1.sidechain_number,
                        description_hash: m1.description.sha256d_hash(),
                    };
                    let accepted = block_info.sidechain_proposals().any(|(proposal_vout, p)| {
                        proposal_vout == vout as u32 && p.compute_id() == proposal_id
                    });
                    let delta = M1Delta {
                        sidechain_number: m1.sidechain_number.0.into(),
                        description: MessageField::some(ConsensusHex::encode(&m1.description.0)),
                        description_sha256d_hash: MessageField::some(ReverseHex::encode(
                            &proposal_id.description_hash,
                        )),
                    };
                    (accepted, bip300coinbase_message::Message::from(delta))
                }
                CoinbaseMessage::M2AckSidechain(m2) => {
                    let proposal_id = crate::types::SidechainProposalId {
                        sidechain_number: m2.sidechain_number,
                        description_hash: m2.description_hash,
                    };
                    let effect = block_diff.coinbase.msgs.iter().find_map(|msg| match msg {
                        BlockCoinbaseMsg::AckSidechainProposal(ack) if ack.id == proposal_id => {
                            Some(match ack.effect {
                                BlockAckSidechainProposalEffect::NoActivation => {
                                    m2delta::Effect::NoActivation
                                }
                                BlockAckSidechainProposalEffect::SlotActivation => {
                                    m2delta::Effect::SlotActivation
                                }
                                BlockAckSidechainProposalEffect::ReplaceActive(_) => {
                                    m2delta::Effect::ReplaceActive
                                }
                            })
                        }
                        _ => None,
                    });
                    let accepted = effect.is_some();
                    let delta = M2Delta {
                        sidechain_number: m2.sidechain_number.0.into(),
                        description_sha256d_hash: MessageField::some(ReverseHex::encode(
                            &m2.description_hash,
                        )),
                        effect: effect.unwrap_or(m2delta::Effect::RejectedOrNoop).into(),
                    };
                    (accepted, bip300coinbase_message::Message::from(delta))
                }
                CoinbaseMessage::M3ProposeBundle(m3) => {
                    let m6id = M6id::from(m3.bundle_txid);
                    let accepted = block_diff.coinbase.msgs.iter().any(|msg| {
                        matches!(msg, BlockCoinbaseMsg::ProposeBundle(proposal)
                            if proposal.sidechain_number == m3.sidechain_number
                                && proposal.m6id == m6id)
                    });
                    let delta = M3Delta {
                        sidechain_number: m3.sidechain_number.0.into(),
                        m6id: MessageField::some(ConsensusHex::encode(&m6id.0)),
                    };
                    (accepted, bip300coinbase_message::Message::from(delta))
                }
                CoinbaseMessage::M4AckBundles(m4) => {
                    let (mode, raw_votes) = match m4 {
                        M4AckBundles::RepeatPrevious => (m4delta::Mode::RepeatPrevious, Vec::new()),
                        M4AckBundles::OneByte { upvotes } => (
                            m4delta::Mode::OneByte,
                            upvotes.into_iter().map(u32::from).collect(),
                        ),
                        M4AckBundles::TwoBytes { upvotes } => (
                            m4delta::Mode::TwoBytes,
                            upvotes.into_iter().map(u32::from).collect(),
                        ),
                        M4AckBundles::LeadingBy50 => (m4delta::Mode::LeadingBy50, Vec::new()),
                    };
                    let delta = M4Delta {
                        mode: mode.into(),
                        raw_votes,
                        effects: m4_effects(block_diff),
                    };
                    (true, bip300coinbase_message::Message::from(delta))
                }
                CoinbaseMessage::M7BmmAccept(m7) => {
                    let accepted = block_info.bmm_commitments.get(&m7.sidechain_number)
                        == Some(&m7.sidechain_block_hash);
                    let delta = M7Delta {
                        sidechain_number: m7.sidechain_number.0.into(),
                        hstar: MessageField::some(ConsensusHex::encode(&m7.sidechain_block_hash)),
                    };
                    (accepted, bip300coinbase_message::Message::from(delta))
                }
            };
            Some(Bip300CoinbaseMessage {
                vout: vout as u32,
                raw_script_pubkey: MessageField::some(Hex::encode(
                    &output.script_pubkey.as_bytes(),
                )),
                accepted,
                message: Some(message),
            })
        })
        .collect()
}

impl Server {
    fn previous_treasury_ctip(
        &self,
        sidechain_number: SidechainNumber,
        sequence_number: u64,
    ) -> Result<Option<TreasuryCtip>, ConnectError> {
        let Some(previous_sequence) = sequence_number.checked_sub(1) else {
            return Ok(None);
        };
        let previous = self
            .validator
            .get_treasury_utxo(sidechain_number, previous_sequence)
            .map_err(internal_err)?;
        Ok(Some(historical_treasury_ctip(&previous)))
    }

    fn treasury_transitions(
        &self,
        header_info: &HeaderInfo,
        block: &Block,
        block_info: &ValidatorBlockInfo,
        block_diff: &BlockDiff,
    ) -> Result<Vec<TreasuryTransition>, ConnectError> {
        let mut transitions = Vec::new();

        for tx_diff in &block_diff.txs {
            match tx_diff {
                BlockTx::M5(m5) => {
                    let mut ctips = m5.new_ctips.iter().collect::<Vec<_>>();
                    ctips.sort_by_key(|(sidechain_number, _)| sidechain_number.0);
                    for (sidechain_number, new_ctip) in ctips {
                        let deposit = block_info.events.iter().find_map(|event| match event {
                            BlockEvent::Deposits(deposits) => deposits
                                .get(sidechain_number)
                                .filter(|deposit| deposit.outpoint == new_ctip.outpoint),
                            _ => None,
                        });
                        let deposit = deposit.ok_or_else(|| {
                            ConnectError::internal(format!(
                                "M5 diff for sidechain {sidechain_number} has no matching block event"
                            ))
                        })?;
                        let transaction = block
                            .txdata
                            .iter()
                            .find(|tx| tx.compute_txid() == new_ctip.outpoint.txid)
                            .ok_or_else(|| {
                                ConnectError::internal(format!(
                                    "M5 diff references transaction {} outside its block",
                                    new_ctip.outpoint.txid
                                ))
                            })?;
                        transitions.push(TreasuryTransition {
                            kind: treasury_transition::Kind::Deposit.into(),
                            sidechain_number: sidechain_number.0.into(),
                            previous_ctip: self
                                .previous_treasury_ctip(*sidechain_number, deposit.sequence_number)?
                                .map(MessageField::some)
                                .unwrap_or_default(),
                            new_ctip: MessageField::some(treasury_ctip(new_ctip)),
                            sequence_number: Some(deposit.sequence_number),
                            delta_sats: Some(deposit.value.to_sat()),
                            payout_sats: None,
                            fee_sats: None,
                            m6id: MessageField::none(),
                            sidechain_address: MessageField::some(Hex::encode(&deposit.address)),
                            transaction: MessageField::some(ConsensusHex::encode(transaction)),
                            proposal_height: None,
                            terminal_height: Some(header_info.height),
                        });
                    }
                }
                BlockTx::M6(m6) => {
                    let success = block_info.withdrawal_bundle_events().find(|event| {
                        event.sidechain_id == m6.sidechain_number
                            && event.m6id == m6.removed_pending_withdrawal
                            && matches!(event.kind, WithdrawalBundleEventKind::Succeeded { .. })
                    });
                    let success = success.ok_or_else(|| {
                        ConnectError::internal(format!(
                            "M6 diff for sidechain {} has no matching success event",
                            m6.sidechain_number
                        ))
                    })?;
                    let WithdrawalBundleEventKind::Succeeded {
                        sequence_number,
                        transaction,
                    } = &success.kind
                    else {
                        unreachable!("filtered for successful withdrawal")
                    };
                    let previous_sequence = sequence_number.checked_sub(1).ok_or_else(|| {
                        ConnectError::internal("a successful M6 cannot be treasury sequence zero")
                    })?;
                    let previous = self
                        .validator
                        .get_treasury_utxo(m6.sidechain_number, previous_sequence)
                        .map_err(internal_err)?;
                    let payout = transaction
                        .output
                        .iter()
                        .skip(1)
                        .map(|output| output.value)
                        .checked_sum()
                        .ok_or_else(|| ConnectError::internal("M6 payout amount overflow"))?;
                    let outputs_total = m6
                        .new_ctip
                        .value
                        .checked_add(payout)
                        .ok_or_else(|| ConnectError::internal("M6 output amount overflow"))?;
                    let fee = previous
                        .total_value
                        .checked_sub(outputs_total)
                        .ok_or_else(|| {
                            ConnectError::internal(
                                "M6 output amount exceeds previous treasury value",
                            )
                        })?;
                    transitions.push(TreasuryTransition {
                        kind: treasury_transition::Kind::WithdrawalSucceeded.into(),
                        sidechain_number: m6.sidechain_number.0.into(),
                        previous_ctip: MessageField::some(historical_treasury_ctip(&previous)),
                        new_ctip: MessageField::some(treasury_ctip(&m6.new_ctip)),
                        sequence_number: Some(*sequence_number),
                        delta_sats: Some(
                            previous
                                .total_value
                                .checked_sub(m6.new_ctip.value)
                                .expect("a valid M6 reduces the treasury")
                                .to_sat(),
                        ),
                        payout_sats: Some(payout.to_sat()),
                        fee_sats: Some(fee.to_sat()),
                        m6id: MessageField::some(ConsensusHex::encode(
                            &m6.removed_pending_withdrawal.0,
                        )),
                        sidechain_address: MessageField::none(),
                        transaction: MessageField::some(ConsensusHex::encode(transaction)),
                        proposal_height: Some(m6.removed_pending_withdrawal_info.proposal_height),
                        terminal_height: Some(header_info.height),
                    });
                }
            }
        }

        let mut failed = block_diff
            .coinbase
            .failed_m6ids
            .0
            .iter()
            .flat_map(|(sidechain_number, failed)| {
                failed
                    .values()
                    .map(move |(m6id, info)| (*sidechain_number, *m6id, *info))
            })
            .collect::<Vec<_>>();
        failed.sort_by_key(|(sidechain_number, m6id, _)| {
            (sidechain_number.0, m6id.0.to_byte_array())
        });
        transitions.extend(failed.into_iter().map(|(sidechain_number, m6id, info)| {
            TreasuryTransition {
                kind: treasury_transition::Kind::WithdrawalFailed.into(),
                sidechain_number: sidechain_number.0.into(),
                previous_ctip: MessageField::none(),
                new_ctip: MessageField::none(),
                sequence_number: None,
                delta_sats: None,
                payout_sats: None,
                fee_sats: None,
                m6id: MessageField::some(ConsensusHex::encode(&m6id.0)),
                sidechain_address: MessageField::none(),
                transaction: MessageField::none(),
                proposal_height: Some(info.proposal_height),
                terminal_height: Some(header_info.height),
            }
        }));

        Ok(transitions)
    }

    fn confirmed_bmm_requests(
        &self,
        block: &Block,
        block_info: &ValidatorBlockInfo,
    ) -> Vec<ConfirmedBmmRequest> {
        block
            .txdata
            .iter()
            .skip(1)
            .filter_map(|transaction| {
                let request = parse_m8_tx(transaction)?;
                (block_info.bmm_commitments.get(&request.sidechain_number)
                    == Some(&request.sidechain_block_hash)
                    && request.prev_mainchain_block_hash == block.header.prev_blockhash)
                    .then(|| ConfirmedBmmRequest {
                        sidechain_number: request.sidechain_number.0.into(),
                        txid: MessageField::some(ReverseHex::encode(&transaction.compute_txid())),
                        transaction: MessageField::some(ConsensusHex::encode(transaction)),
                        hstar: MessageField::some(ConsensusHex::encode(
                            &request.sidechain_block_hash,
                        )),
                        previous_mainchain_block_hash: MessageField::some(ReverseHex::encode(
                            &request.prev_mainchain_block_hash,
                        )),
                        fee_sats: None,
                    })
            })
            .collect()
    }

    fn bip300_block_delta(
        &self,
        header_info: HeaderInfo,
        block: &Block,
        block_info: &ValidatorBlockInfo,
        block_diff: &BlockDiff,
    ) -> Result<Bip300BlockDelta, ConnectError> {
        let treasury_transitions =
            self.treasury_transitions(&header_info, block, block_info, block_diff)?;
        Ok(Bip300BlockDelta {
            header_info: MessageField::some(header_info.into()),
            coinbase_txid: MessageField::some(ReverseHex::encode(&block_info.coinbase_txid)),
            coinbase_messages: coinbase_messages(block, block_info, block_diff),
            treasury_transitions,
            confirmed_bmm_requests: self.confirmed_bmm_requests(block, block_info),
        })
    }
}

/// Age of a sidechain proposal at the given mainchain tip height. A proposal
/// retained from a previous sync can have a `proposal_height` above the active
/// tip, so this saturates instead of underflowing, matching the same
/// computation in `validator::task`.
fn proposal_age(mainchain_tip_height: u32, proposal_height: u32) -> u32 {
    mainchain_tip_height.saturating_sub(proposal_height)
}

#[expect(refining_impl_trait_reachable)]
impl ValidatorService for Server {
    async fn get_block_header_info(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetBlockHeaderInfoRequest>,
    ) -> ServiceResult<GetBlockHeaderInfoResponse> {
        use crate::proto::mainchain::GetBlockHeaderInfoRequest;
        let GetBlockHeaderInfoRequest {
            block_hash,
            max_ancestors,
            ..
        } = request.to_owned_message();
        let block_hash = block_hash
            .into_option()
            .ok_or_else(|| missing_field::<GetBlockHeaderInfoRequest>("block_hash"))?
            .decode_status::<GetBlockHeaderInfoRequest, _>("block_hash")?;
        let max_ancestors = max_ancestors.unwrap_or(0) as usize;
        let resp = match self
            .validator
            .try_get_header_infos(&block_hash, max_ancestors)
            .map_err(internal_err)?
        {
            Some(infos) => GetBlockHeaderInfoResponse {
                header_infos: infos.into_iter().map(Into::into).collect(),
            },
            None => GetBlockHeaderInfoResponse::default(),
        };
        Ok(Response::new(resp))
    }

    async fn get_block_info(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetBlockInfoRequest>,
    ) -> ServiceResult<GetBlockInfoResponse> {
        use crate::proto::mainchain::GetBlockInfoRequest;
        let GetBlockInfoRequest {
            block_hash,
            sidechain_id,
            max_ancestors,
            ..
        } = request.to_owned_message();
        let block_hash = block_hash
            .into_option()
            .ok_or_else(|| missing_field::<GetBlockInfoRequest>("block_hash"))?
            .decode_status::<GetBlockInfoRequest, _>("block_hash")?;
        let sidechain_id = parse_sidechain_id::<GetBlockInfoRequest>(sidechain_id, "sidechain_id")?;
        let max_ancestors = max_ancestors.unwrap_or(0) as usize;
        let resp = match self
            .validator
            .try_get_block_infos(&block_hash, max_ancestors)
            .map_err(internal_err)?
        {
            None => GetBlockInfoResponse::default(),
            Some(infos) => GetBlockInfoResponse {
                infos: infos
                    .into_iter()
                    .map(|(header_info, block_info)| get_block_info_response::Info {
                        header_info: MessageField::some(header_info.into()),
                        block_info: MessageField::some(block_info.as_proto(sidechain_id)),
                    })
                    .collect(),
            },
        };
        Ok(Response::new(resp))
    }

    async fn get_bip300_block_delta(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetBip300BlockDeltaRequest>,
    ) -> ServiceResult<GetBip300BlockDeltaResponse> {
        let GetBip300BlockDeltaRequest {
            block_hash,
            max_ancestors,
            ..
        } = request.to_owned_message();
        let block_hash = block_hash
            .into_option()
            .ok_or_else(|| missing_field::<GetBip300BlockDeltaRequest>("block_hash"))?
            .decode_status::<GetBip300BlockDeltaRequest, _>("block_hash")?;
        let max_ancestors = max_ancestors.unwrap_or(0);
        if max_ancestors > MAX_BIP300_BLOCK_DELTA_ANCESTORS {
            return Err(ConnectError::invalid_argument(format!(
                "max_ancestors exceeds the observer RPC limit of {MAX_BIP300_BLOCK_DELTA_ANCESTORS}"
            )));
        }
        let Some(infos) = self
            .validator
            .try_get_block_infos(&block_hash, max_ancestors as usize)
            .map_err(internal_err)?
        else {
            return Ok(Response::new(GetBip300BlockDeltaResponse::default()));
        };

        let mut deltas = Vec::with_capacity(infos.len());
        for (header_info, block_info) in infos {
            let block = self
                .validator
                .get_raw_block(header_info.block_hash)
                .await
                .map_err(internal_err)?;
            if block.block_hash() != header_info.block_hash {
                return Err(ConnectError::internal(format!(
                    "Core returned block {} for requested block {}",
                    block.block_hash(),
                    header_info.block_hash
                )));
            }
            let block_diff = self
                .validator
                .get_block_diff(&header_info.block_hash)
                .map_err(internal_err)?;
            deltas.push(self.bip300_block_delta(header_info, &block, &block_info, &block_diff)?);
        }
        Ok(Response::new(GetBip300BlockDeltaResponse { deltas }))
    }

    async fn get_bmm_h_star_commitment(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetBmmHStarCommitmentRequest>,
    ) -> ServiceResult<GetBmmHStarCommitmentResponse> {
        use crate::proto::mainchain::GetBmmHStarCommitmentRequest;
        let GetBmmHStarCommitmentRequest {
            block_hash,
            sidechain_id,
            max_ancestors,
            ..
        } = request.to_owned_message();
        let block_hash = block_hash
            .into_option()
            .ok_or_else(|| missing_field::<GetBmmHStarCommitmentRequest>("block_hash"))?
            .decode_status::<GetBmmHStarCommitmentRequest, _>("block_hash")?;
        let sidechain_id =
            parse_sidechain_id::<GetBmmHStarCommitmentRequest>(sidechain_id, "sidechain_id")?;
        let max_ancestors = max_ancestors.unwrap_or(0) as usize;
        let bmm_commitments = self
            .validator
            .try_get_bmm_commitments(&block_hash, max_ancestors)
            .map_err(internal_err)?;
        let res = match nonempty::NonEmpty::from_vec(bmm_commitments) {
            None => get_bmm_h_star_commitment_response::Result::BlockNotFound(Box::new(
                get_bmm_h_star_commitment_response::BlockNotFoundError {
                    block_hash: MessageField::some(ReverseHex::encode(&block_hash)),
                },
            )),
            Some(nonempty::NonEmpty { head, tail }) => {
                let commitment = head
                    .get(&sidechain_id)
                    .map(|c| MessageField::some(ConsensusHex::encode(c)))
                    .unwrap_or_default();
                let ancestor_commitments = tail
                    .into_iter()
                    .map(
                        |commitments| get_bmm_h_star_commitment_response::OptionalCommitment {
                            commitment: commitments
                                .get(&sidechain_id)
                                .map(|c| MessageField::some(ConsensusHex::encode(c)))
                                .unwrap_or_default(),
                        },
                    )
                    .collect();
                get_bmm_h_star_commitment_response::Result::Commitment(Box::new(
                    get_bmm_h_star_commitment_response::Commitment {
                        commitment,
                        ancestor_commitments,
                    },
                ))
            }
        };
        Ok(Response::new(GetBmmHStarCommitmentResponse {
            result: Some(res),
        }))
    }

    async fn get_chain_info(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetChainInfoRequest>,
    ) -> ServiceResult<GetChainInfoResponse> {
        let bitcoin_network = self.validator.network();
        let network: Network = bitcoin_network.into();
        let network_params = self.validator.network_params();
        let Thresholds {
            withdrawal_bundle_max_age,
            withdrawal_bundle_inclusion_threshold,
            used_sidechain_slot_proposal_max_age,
            used_sidechain_slot_activation_threshold,
            unused_sidechain_slot_proposal_max_age,
            unused_sidechain_slot_activation_threshold,
        } = network_params.thresholds;
        Ok(Response::new(GetChainInfoResponse {
            network: network.into(),
            bip300_constants: MessageField::some(Bip300Constants {
                withdrawal_bundle_max_age: withdrawal_bundle_max_age.into(),
                withdrawal_bundle_inclusion_threshold: withdrawal_bundle_inclusion_threshold.into(),
                used_sidechain_slot_proposal_max_age: used_sidechain_slot_proposal_max_age.into(),
                used_sidechain_slot_activation_threshold: used_sidechain_slot_activation_threshold
                    .into(),
                unused_sidechain_slot_proposal_max_age: unused_sidechain_slot_proposal_max_age
                    .into(),
                unused_sidechain_slot_activation_threshold:
                    unused_sidechain_slot_activation_threshold.into(),
                activation_height: network_params.bip300_activation_height,
            }),
        }))
    }

    async fn get_chain_tip(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetChainTipRequest>,
    ) -> ServiceResult<GetChainTipResponse> {
        let Some(tip_hash) = self
            .validator
            .try_get_mainchain_tip()
            .map_err(|err| err.builder().to_connect_error())?
        else {
            return Err(ConnectError::unavailable("Validator is not synced"));
        };
        let header_info = self
            .validator
            .get_header_info(&tip_hash)
            .map_err(internal_err)?;
        Ok(Response::new(GetChainTipResponse {
            block_header_info: MessageField::some(header_info.into()),
        }))
    }

    async fn get_coinbase_psbt(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetCoinbasePSBTRequest>,
    ) -> ServiceResult<GetCoinbasePSBTResponse> {
        use crate::proto::mainchain::GetCoinbasePSBTRequest;
        let request = request.to_owned_message();
        let mut messages = Vec::<CoinbaseMessage>::new();
        for propose in request.propose_sidechains {
            let m1: M1ProposeSidechain = propose.try_into()?;
            messages.push(m1.into());
        }
        for ack in request.ack_sidechains {
            let m2: M2AckSidechain = ack.try_into()?;
            messages.push(m2.into());
        }
        for propose in request.propose_bundles {
            let m3: M3ProposeBundle = propose.try_into()?;
            messages.push(m3.into());
        }
        let ack_bundles = request
            .ack_bundles
            .into_option()
            .ok_or_else(|| missing_field::<GetCoinbasePSBTRequest>("ack_bundles"))?;
        let m4: CoinbaseMessage = ack_bundles.try_into()?;
        messages.push(m4);
        let output = messages
            .into_iter()
            .map(|m| {
                Ok(TxOut {
                    value: Amount::ZERO,
                    script_pubkey: m.try_into().into_diagnostic()?,
                })
            })
            .collect::<miette::Result<Vec<_>>>()
            .map_err(internal_err)?;
        let transaction = Transaction {
            output,
            input: vec![],
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            version: bitcoin::transaction::Version::TWO,
        };
        Ok(Response::new(GetCoinbasePSBTResponse {
            psbt: MessageField::some(ConsensusHex::encode(&transaction)),
        }))
    }

    async fn get_ctip(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetCtipRequest>,
    ) -> ServiceResult<GetCtipResponse> {
        use crate::proto::mainchain::GetCtipRequest;
        let GetCtipRequest {
            sidechain_number, ..
        } = request.to_owned_message();
        let sidechain_number =
            parse_sidechain_id::<GetCtipRequest>(sidechain_number, "sidechain_number")?;
        let ctip = self
            .validator
            .try_get_ctip(sidechain_number)
            .map_err(|err| err.builder().to_connect_error())?;
        let response = if let Some(ctip) = ctip {
            let sequence_number = self
                .validator
                .get_ctip_sequence_number(sidechain_number)
                .map_err(|err| err.builder().to_connect_error())?
                // get_ctip returned Some(ctip) above, so we know that the sequence_number will also
                // return Some, so we just unwrap it.
                .unwrap();
            GetCtipResponse {
                ctip: MessageField::some(Ctip {
                    txid: MessageField::some(ReverseHex::encode(&ctip.outpoint.txid)),
                    vout: ctip.outpoint.vout,
                    value: ctip.value.to_sat(),
                    sequence_number,
                }),
            }
        } else {
            GetCtipResponse::default()
        };
        Ok(Response::new(response))
    }

    async fn get_sidechain_proposals(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetSidechainProposalsRequest>,
    ) -> ServiceResult<GetSidechainProposalsResponse> {
        let Some(tip) = self
            .validator
            .try_get_mainchain_tip()
            .map_err(|err| err.builder().to_connect_error())?
        else {
            return Ok(Response::new(GetSidechainProposalsResponse::default()));
        };
        let mainchain_tip_height = self
            .validator
            .get_header_info(&tip)
            .map_err(|err| err.builder().to_connect_error())?
            .height;
        let proposals = self
            .validator
            .get_sidechains()
            .map_err(|err| err.builder().to_connect_error())?;
        let sidechain_proposals = proposals
            .into_iter()
            .map(|(proposal_id, sidechain)| {
                let description = ConsensusHex::encode(&sidechain.proposal.description.0);
                let declaration =
                    crate::types::SidechainDeclaration::try_from(&sidechain.proposal.description)
                        .map(crate::proto::mainchain::SidechainDeclaration::from)
                        .ok();
                SidechainProposal {
                    sidechain_number: wrap_u32(sidechain.proposal.sidechain_number.0 as u32),
                    description: MessageField::some(description),
                    declaration: declaration.map(MessageField::some).unwrap_or_default(),
                    description_sha256d_hash: MessageField::some(ReverseHex::encode(
                        &proposal_id.description_hash,
                    )),
                    vote_count: wrap_u32(sidechain.status.vote_count as u32),
                    proposal_height: wrap_u32(sidechain.status.proposal_height),
                    proposal_age: wrap_u32(proposal_age(
                        mainchain_tip_height,
                        sidechain.status.proposal_height,
                    )),
                }
            })
            .collect();
        Ok(Response::new(GetSidechainProposalsResponse {
            sidechain_proposals,
        }))
    }

    async fn get_sidechains(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetSidechainsRequest>,
    ) -> ServiceResult<GetSidechainsResponse> {
        let sidechains = self
            .validator
            .get_active_sidechains()
            .map_err(|err| err.builder().to_connect_error())?;
        let sidechains = sidechains.into_iter().map(SidechainInfo::from).collect();
        Ok(Response::new(GetSidechainsResponse { sidechains }))
    }

    async fn get_two_way_peg_data(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetTwoWayPegDataRequest>,
    ) -> ServiceResult<GetTwoWayPegDataResponse> {
        use crate::proto::mainchain::GetTwoWayPegDataRequest;
        let GetTwoWayPegDataRequest {
            sidechain_id,
            start_block_hash,
            end_block_hash,
            ..
        } = request.to_owned_message();
        let sidechain_id =
            parse_sidechain_id::<GetTwoWayPegDataRequest>(sidechain_id, "sidechain_id")?;
        let start_block_hash: Option<BlockHash> = start_block_hash
            .into_option()
            .map(|h| h.decode_status::<GetTwoWayPegDataRequest, _>("start_block_hash"))
            .transpose()?
            .map(|bytes| {
                convert::bdk_block_hash_to_bitcoin_block_hash(
                    bdk_wallet::bitcoin::BlockHash::from_byte_array(bytes),
                )
            });
        let end_block_hash: BlockHash = end_block_hash
            .into_option()
            .ok_or_else(|| missing_field::<GetTwoWayPegDataRequest>("end_block_hash"))?
            .decode_status::<GetTwoWayPegDataRequest, _>("end_block_hash")
            .map(bdk_wallet::bitcoin::BlockHash::from_byte_array)
            .map(convert::bdk_block_hash_to_bitcoin_block_hash)?;
        let two_way_peg_data = self
            .validator
            .get_two_way_peg_data(start_block_hash, end_block_hash)
            .map_err(internal_err)?;
        let blocks = two_way_peg_data
            .into_iter()
            .filter_map(|d| d.into_proto(sidechain_id))
            .collect();
        Ok(Response::new(GetTwoWayPegDataResponse { blocks }))
    }

    async fn get_withdrawal_bundle_proposals(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetWithdrawalBundleProposalsRequest>,
    ) -> ServiceResult<GetWithdrawalBundleProposalsResponse> {
        use get_withdrawal_bundle_proposals_response::ResponseItem;
        let GetWithdrawalBundleProposalsRequest { sidechain_id } = request.to_owned_message();
        let sidechain_id =
            parse_sidechain_id::<GetTwoWayPegDataRequest>(sidechain_id, "sidechain_id")?;
        let proposals = self
            .validator
            .get_pending_withdrawals(&sidechain_id)
            .map_err(internal_err)?
            .into_iter()
            .map(|(m6id, info)| {
                let crate::types::PendingM6idInfo {
                    vote_count,
                    proposal_height,
                } = info;
                ResponseItem {
                    m6id: MessageField::some(ConsensusHex::encode(&m6id.0)),
                    vote_count: MessageField::some((vote_count as u32).into()),
                    proposal_height: MessageField::some(proposal_height.into()),
                }
            })
            .collect();
        let resp = GetWithdrawalBundleProposalsResponse { proposals };
        Ok(Response::new(resp))
    }

    async fn subscribe_events(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, SubscribeEventsRequest>,
    ) -> ServiceResult<connectrpc::ServiceStream<SubscribeEventsResponse>> {
        use crate::proto::mainchain::SubscribeEventsRequest;
        let SubscribeEventsRequest { sidechain_id, .. } = request.to_owned_message();
        let sidechain_id =
            parse_sidechain_id::<SubscribeEventsRequest>(sidechain_id, "sidechain_id")?;
        let stream: BoxStream<'static, _> = self
            .validator
            .subscribe_events()
            .map(move |res| match res {
                Ok(event) => Ok(SubscribeEventsResponse {
                    event: MessageField::some(event.into_proto(sidechain_id).into()),
                }),
                Err(err) => Err(err.builder().to_connect_error()),
            })
            .boxed();
        Ok(Response::new(Box::pin(stream)))
    }

    async fn subscribe_header_sync_progress(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, SubscribeHeaderSyncProgressRequest>,
    ) -> ServiceResult<connectrpc::ServiceStream<SubscribeHeaderSyncProgressResponse>> {
        let Some(rx) = self.validator.subscribe_header_sync_progress() else {
            return Err(ConnectError::unavailable("No header sync in progress"));
        };
        let stream: BoxStream<'static, _> = tokio_stream::wrappers::WatchStream::new(rx)
            .map(|progress| Ok(progress.into()))
            .boxed();
        Ok(Response::new(Box::pin(stream)))
    }

    async fn stop(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, StopRequest>,
    ) -> ServiceResult<StopResponse> {
        if self.cancel.is_cancelled() {
            return Err(ConnectError::unavailable(
                "Validator is already shutting down",
            ));
        }
        tracing::info!("received stop request, cancelling token");
        self.cancel.cancel();
        Ok(Response::new(StopResponse::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::proposal_age;

    #[test]
    fn proposal_age_saturates_below_tip() {
        // A proposal retained from a previous sync can sit above the active
        // tip; its age must saturate to zero rather than underflow.
        assert_eq!(proposal_age(10, 25), 0);
    }

    #[test]
    fn proposal_age_is_tip_minus_proposal_height() {
        assert_eq!(proposal_age(25, 10), 15);
    }
}
