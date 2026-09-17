// Copyright (c) 2012-2013 The PPCoin developers
// Distributed under the GPL3 software license, see the accompanying
// file COPYING or http://www.gnu.org/licenses/gpl.html.
//
// Proof-of-stake kernel ported to the Bitcoin Core 29.x validation
// interfaces (ChainstateManager/BlockManager instead of globals,
// BlockValidationState instead of CValidationState).

#include <kernel.h>

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <hash.h>
#include <kernel/cs_main.h>
#include <logging.h>
#include <node/transaction.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <cinttypes>
#include <map>
#include <utility>
#include <vector>

// Local error helper ( historical `error()` returned false after logging ).
static bool kernel_error(const std::string& msg)
{
    LogError("%s", msg);
    return false;
}

// Hard checkpoints of stake modifiers to ensure they are deterministic
static std::map<int, unsigned int> mapStakeModifierCheckpoints;

// Forward declaration (defined below ComputeNextStakeModifier).
static bool ComputeNextStakeModifierSelect(ChainstateManager& chainman, const Consensus::Params& consensus, int64_t nSelectionIntervalStart, const std::vector<std::pair<int64_t, uint256>>& vSortedByTimestamp, uint64_t nStakeModifier, uint64_t& nStakeModifierNew);

// Get the last stake modifier and its generation time from a given block
static bool GetLastStakeModifier(const CBlockIndex* pindex, uint64_t& nStakeModifier, int64_t& nModifierTime)
{
    if (!pindex)
        return kernel_error("GetLastStakeModifier: null pindex");
    while (pindex && pindex->pprev && !pindex->GeneratedStakeModifier())
        pindex = pindex->pprev;
    if (!pindex->GeneratedStakeModifier())
        return kernel_error("GetLastStakeModifier: no generation at genesis block");
    nStakeModifier = pindex->nStakeModifier;
    nModifierTime = pindex->GetBlockTime();
    return true;
}

// Get selection interval section (in seconds)
static int64_t GetStakeModifierSelectionIntervalSection(int nSection, const Consensus::Params& consensus)
{
    assert(nSection >= 0 && nSection < 64);
    return (consensus.nStakeModifierInterval * 63 / (63 + ((63 - nSection) * (MODIFIER_INTERVAL_RATIO - 1))));
}

// Get stake modifier selection interval (in seconds)
static int64_t GetStakeModifierSelectionInterval(const Consensus::Params& consensus)
{
    int64_t nSelectionInterval = 0;
    for (int nSection = 0; nSection < 64; nSection++)
        nSelectionInterval += GetStakeModifierSelectionIntervalSection(nSection, consensus);
    return nSelectionInterval;
}

// select a block from the candidate blocks in vSortedByTimestamp, excluding
// already selected blocks in vSelectedBlocks, and with timestamp up to
// nSelectionIntervalStop.
static bool SelectBlockFromCandidates(
    ChainstateManager& chainman,
    std::vector<std::pair<int64_t, uint256>>& vSortedByTimestamp,
    std::map<uint256, const CBlockIndex*>& mapSelectedBlocks,
    int64_t nSelectionIntervalStop, uint64_t nStakeModifierPrev,
    const CBlockIndex** pindexSelected)
{
    AssertLockHeld(cs_main);
    bool fSelected = false;
    arith_uint256 hashBest = 0;
    *pindexSelected = nullptr;
    for (const std::pair<int64_t, uint256>& item : vSortedByTimestamp)
    {
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(item.second);
        if (!pindex)
            return kernel_error(strprintf("SelectBlockFromCandidates: failed to find block index for candidate block %s", item.second.ToString()));
        if (fSelected && pindex->GetBlockTime() > nSelectionIntervalStop)
            break;
        if (mapSelectedBlocks.count(pindex->GetBlockHash()) > 0)
            continue;
        // compute the selection hash by hashing its proof-hash and the
        // previous proof-of-stake modifier
        uint256 hashProof = pindex->IsProofOfStake() ? pindex->hashProofOfStake : pindex->GetBlockHash();
        HashWriter ss{};
        ss << hashProof << nStakeModifierPrev;
        arith_uint256 hashSelection = UintToArith256(ss.GetHash());
        // the selection hash is divided by 2**32 so that proof-of-stake block
        // is always favored over proof-of-work block. this is to preserve
        // the energy efficiency property
        if (pindex->IsProofOfStake())
            hashSelection >>= 32;
        if (fSelected && hashSelection < hashBest)
        {
            hashBest = hashSelection;
            *pindexSelected = pindex;
        }
        else if (!fSelected)
        {
            fSelected = true;
            hashBest = hashSelection;
            *pindexSelected = pindex;
        }
    }
    LogDebug(BCLog::STAKEMODIFIER, "SelectBlockFromCandidates: selection hash=%s\n", hashBest.ToString());
    return fSelected;
}

// Stake Modifier (hash modifier of proof-of-stake):
// The purpose of stake modifier is to prevent a txout (coin) owner from
// computing future proof-of-stake generated by this txout at the time
// of transaction confirmation. To meet kernel protocol, the txout
// must hash with a future stake modifier to generate the proof.
// Stake modifier consists of bits each of which is contributed from a
// selected block of a given block group in the past.
// The selection of a block is based on a hash of the block's proof-hash and
// the previous stake modifier.
// Stake modifier is recomputed at a fixed time interval instead of every
// block. This is to make it difficult for an attacker to gain control of
// additional bits in the stake modifier, even after generating a chain of
// blocks.
bool ComputeNextStakeModifier(ChainstateManager& chainman, const CBlockIndex* pindexCurrent, const Consensus::Params& consensus, uint64_t& nStakeModifier, bool& fGeneratedStakeModifier)
{
    AssertLockHeld(cs_main);
    const CBlockIndex* pindexPrev = pindexCurrent->pprev;
    nStakeModifier = 0;
    fGeneratedStakeModifier = false;
    if (!pindexPrev)
    {
        fGeneratedStakeModifier = true;
        return true;  // genesis block's modifier is 0
    }
    // First find current stake modifier and its generation block time
    // if it's not old enough, return the same stake modifier
    int64_t nModifierTime = 0;
    if (!GetLastStakeModifier(pindexPrev, nStakeModifier, nModifierTime))
        return kernel_error("ComputeNextStakeModifier: unable to get last modifier");

    LogDebug(BCLog::STAKEMODIFIER, "ComputeNextStakeModifier: prev modifier=0x%016" PRIx64 " time=%s epoch=%u\n", nStakeModifier, FormatISO8601DateTime(nModifierTime), (unsigned int)nModifierTime);
    if (nModifierTime / consensus.nStakeModifierInterval >= pindexPrev->GetBlockTime() / consensus.nStakeModifierInterval)
    {
        LogDebug(BCLog::STAKEMODIFIER, "ComputeNextStakeModifier: no new interval keep current modifier: pindexPrev nHeight=%d nTime=%u\n", pindexPrev->nHeight, (unsigned int)pindexPrev->GetBlockTime());
        return true;
    }
    if (nModifierTime / consensus.nStakeModifierInterval >= pindexCurrent->GetBlockTime() / consensus.nStakeModifierInterval)
    {
        LogDebug(BCLog::STAKEMODIFIER, "ComputeNextStakeModifier: no new interval keep current modifier: pindexCurrent nHeight=%d nTime=%u\n", pindexCurrent->nHeight, (unsigned int)pindexCurrent->GetBlockTime());
        return true;
    }

    // Sort candidate blocks by timestamp
    std::vector<std::pair<int64_t, uint256>> vSortedByTimestamp;
    vSortedByTimestamp.reserve(64 * consensus.nStakeModifierInterval / consensus.nPosTargetSpacing);
    int64_t nSelectionInterval = GetStakeModifierSelectionInterval(consensus);
    int64_t nSelectionIntervalStart = (pindexPrev->GetBlockTime() / consensus.nStakeModifierInterval) * consensus.nStakeModifierInterval - nSelectionInterval;
    const CBlockIndex* pindex = pindexPrev;
    while (pindex && pindex->GetBlockTime() >= nSelectionIntervalStart)
    {
        vSortedByTimestamp.push_back(std::make_pair(pindex->GetBlockTime(), pindex->GetBlockHash()));
        pindex = pindex->pprev;
    }
    int nHeightFirstCandidate = pindex ? (pindex->nHeight + 1) : 0;
    std::reverse(vSortedByTimestamp.begin(), vSortedByTimestamp.end());
    std::sort(vSortedByTimestamp.begin(), vSortedByTimestamp.end());

    // Select 64 blocks from candidate blocks to generate stake modifier
    uint64_t nStakeModifierNew = 0;
    if (!ComputeNextStakeModifierSelect(chainman, consensus, nSelectionIntervalStart, vSortedByTimestamp, nStakeModifier, nStakeModifierNew))
        return false;

    // Print selection map for visualization of the selected blocks
    if (LogAcceptCategory(BCLog::STAKEMODIFIER, BCLog::Level::Debug))
    {
        std::string strSelectionMap = "";
        // '-' indicates proof-of-work blocks not selected
        strSelectionMap.insert(0, pindexPrev->nHeight - nHeightFirstCandidate + 1, '-');
        pindex = pindexPrev;
        while (pindex && pindex->nHeight >= nHeightFirstCandidate)
        {
            // '=' indicates proof-of-stake blocks not selected
            if (pindex->IsProofOfStake())
                strSelectionMap.replace(pindex->nHeight - nHeightFirstCandidate, 1, "=");
            pindex = pindex->pprev;
        }
        LogDebug(BCLog::STAKEMODIFIER, "ComputeNextStakeModifier: selection height [%d, %d] map %s\n", nHeightFirstCandidate, pindexPrev->nHeight, strSelectionMap);
    }
    LogDebug(BCLog::STAKEMODIFIER, "ComputeNextStakeModifier: new modifier=0x%016" PRIx64 " time=%s\n", nStakeModifierNew, FormatISO8601DateTime(pindexPrev->GetBlockTime()));
    nStakeModifier = nStakeModifierNew;
    fGeneratedStakeModifier = true;
    return true;
}

// Full selection pass; separated so the only mapBlockIndex-equivalent access
// (hash -> index lookups) goes through ChainstateManager.
static bool ComputeNextStakeModifierSelect(ChainstateManager& chainman, const Consensus::Params& consensus, int64_t nSelectionIntervalStart, const std::vector<std::pair<int64_t, uint256>>& vSortedByTimestamp, uint64_t nStakeModifier, uint64_t& nStakeModifierNew)
{
    int64_t nSelectionIntervalStop = nSelectionIntervalStart;
    std::map<uint256, const CBlockIndex*> mapSelectedBlocks;
    const CBlockIndex* pindex = nullptr;
    nStakeModifierNew = 0;
    for (int nRound = 0; nRound < std::min(64, (int)vSortedByTimestamp.size()); nRound++)
    {
        // add an interval section to the current selection round
        nSelectionIntervalStop += GetStakeModifierSelectionIntervalSection(nRound, consensus);
        // select a block from the candidates of current round
        std::vector<std::pair<int64_t, uint256>>& vMutable = const_cast<std::vector<std::pair<int64_t, uint256>>&>(vSortedByTimestamp);
        if (!SelectBlockFromCandidates(chainman, vMutable, mapSelectedBlocks, nSelectionIntervalStop, nStakeModifier, &pindex))
            return kernel_error(strprintf("ComputeNextStakeModifier: unable to select block at round %d", nRound));
        // write the entropy bit of the selected block
        nStakeModifierNew |= (((uint64_t)pindex->GetStakeEntropyBit()) << nRound);
        // add the selected block from candidates to selected list
        mapSelectedBlocks.insert(std::make_pair(pindex->GetBlockHash(), pindex));
        LogDebug(BCLog::STAKEMODIFIER, "ComputeNextStakeModifier: selected round %d stop=%s height=%d bit=%d\n",
                nRound, FormatISO8601DateTime(nSelectionIntervalStop), pindex->nHeight, pindex->GetStakeEntropyBit());
    }
    return true;
}

// The stake modifier used to hash for a stake kernel is chosen as the stake
// modifier about a selection interval later than the coin generating the kernel
static bool GetKernelStakeModifier(const Consensus::Params& consensus, const CBlockIndex* pindexTip, unsigned int nCoinStakeTime, uint64_t& nStakeModifier, int& nStakeModifierHeight, int64_t& nStakeModifierTime, bool fPrintProofOfStake)
{
    const CBlockIndex* pindex = pindexTip;
    nStakeModifierHeight = pindex->nHeight;
    nStakeModifierTime = pindex->GetBlockTime();
    int64_t nStakeModifierSelectionInterval = GetStakeModifierSelectionInterval(consensus);

    if (nStakeModifierTime + consensus.nStakeMinAge - nStakeModifierSelectionInterval <= (int64_t)nCoinStakeTime)
    {
        // Best block is still more than
        // (nStakeMinAge minus a selection interval) older than kernel timestamp
        if (fPrintProofOfStake)
            return kernel_error(strprintf("GetKernelStakeModifier() : best block %s at height %d too old for stake",
                pindex->GetBlockHash().ToString(), pindex->nHeight));
        else
            return false;
    }
    // loop to find the stake modifier earlier by
    // (nStakeMinAge minus a selection interval)
    while (nStakeModifierTime + consensus.nStakeMinAge - nStakeModifierSelectionInterval > (int64_t)nCoinStakeTime)
    {
        if (!pindex->pprev)
        {   // reached genesis block; should not happen
            return kernel_error("GetKernelStakeModifier() : reached genesis block");
        }
        pindex = pindex->pprev;
        if (pindex->GeneratedStakeModifier())
        {
            nStakeModifierHeight = pindex->nHeight;
            nStakeModifierTime = pindex->GetBlockTime();
        }
    }
    nStakeModifier = pindex->nStakeModifier;
    return true;
}

// ppcoin kernel protocol
// coinstake must meet hash target according to the protocol:
// kernel (input 0) must meet the formula
//     hash(nStakeModifier + txPrev.block.nTime + txPrev.offset + txPrev.nTime + txPrev.vout.n + nTime) < bnTarget * nCoinDayWeight
// this ensures that the chance of getting a coinstake is proportional to the
// amount of coin age one owns.
bool CheckStakeKernelHash(const Consensus::Params& consensus, const CBlockIndex* pindexTip, unsigned int nBits, const CBlockHeader& blockFrom, unsigned int nTxPrevOffset, const CTxOut& txOutPrev, const COutPoint& prevout, uint32_t nTimeTx, uint256& hashProofOfStake, bool fPrintProofOfStake)
{
    uint32_t nTimeBlockFrom = blockFrom.GetBlockTime();
    if (nTimeBlockFrom + consensus.nStakeMinAge > nTimeTx) // Min age requirement
        return kernel_error("CheckStakeKernelHash() : min age violation");

    arith_uint256 bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
    // v0.3 protocol kernel hash weight starts from 0 at the min age
    // this change increases active coins participating the hash and helps
    // to secure the network when proof-of-stake difficulty is low
    int64_t nTimeWeight = std::min((int64_t)nTimeTx - nTimeBlockFrom, consensus.nStakeMaxAge) - consensus.nStakeMinAge;
    arith_uint256 bnCoinDayWeight = arith_uint256(txOutPrev.nValue) * nTimeWeight / COIN / (24 * 60 * 60);
    // Calculate hash
    uint64_t nStakeModifier = 0;
    int nStakeModifierHeight = 0;
    int64_t nStakeModifierTime = 0;
    if (!GetKernelStakeModifier(consensus, pindexTip, blockFrom.GetBlockTime(), nStakeModifier, nStakeModifierHeight, nStakeModifierTime, fPrintProofOfStake))
        return false;

    HashWriter ss{};
    ss << nStakeModifier << nTimeBlockFrom << nTxPrevOffset << nTimeBlockFrom << prevout.n << nTimeTx;

    hashProofOfStake = ss.GetHash();
    // Note: BCA hashed the same six fields with double-SHA256; HashWriter
    // reproduces those exact bytes (fixed-width little-endian integers).
    if (fPrintProofOfStake) {
        LogPrintf("CheckStakeKernelHash() : using modifier 0x%016" PRIx64 " at height=%d timestamp=%s for block from timestamp=%s\n",
            nStakeModifier, nStakeModifierHeight,
            FormatISO8601DateTime(nStakeModifierTime),
            FormatISO8601DateTime(blockFrom.GetBlockTime()));
        LogPrintf("CheckStakeKernelHash() : modifier=0x%016" PRIx64 " nTimeBlockFrom=%u nTxPrevOffset=%u nPrevout=%u nTimeTx=%u hashProof=%s\n",
            nStakeModifier,
            nTimeBlockFrom, nTxPrevOffset, prevout.n, nTimeTx,
            hashProofOfStake.ToString());
    }
    // Now check if proof-of-stake hash meets target protocol
    if (UintToArith256(hashProofOfStake) > bnCoinDayWeight * bnTargetPerCoinDay)
        return false;

    if (!fPrintProofOfStake) {
        LogDebug(BCLog::STAKEMODIFIER, "CheckStakeKernelHash() : using modifier 0x%016" PRIx64 " at height=%d timestamp=%s for block from timestamp=%s\n",
            nStakeModifier, nStakeModifierHeight,
            FormatISO8601DateTime(nStakeModifierTime),
            FormatISO8601DateTime(blockFrom.GetBlockTime()));
        LogDebug(BCLog::STAKEMODIFIER, "CheckStakeKernelHash() : modifier=0x%016" PRIx64 " nTimeBlockFrom=%u nTxPrevOffset=%u nPrevout=%u nTimeTx=%u hashProof=%s\n",
            nStakeModifier,
            nTimeBlockFrom, nTxPrevOffset, prevout.n, nTimeTx,
            hashProofOfStake.ToString());
    }
    return true;
}

// Check kernel hash target and coinstake signature
bool CheckProofOfStake(BlockValidationState& state, ChainstateManager& chainman, const CTxMemPool* mempool, const CTransactionRef& tx, unsigned int nBits, uint256& hashProofOfStake, unsigned int nBlockTime)
{
    AssertLockHeld(cs_main);
    const Consensus::Params& consensus = chainman.GetConsensus();
    // Kernel (input 0) must match the stake hash target per coin age (nBits)
    const CTxIn& txin = tx->vin[0];

    // First try finding the previous transaction (mempool, then txindex-backed lookup)
    uint256 hashBlock;
    CTransactionRef txPrev = node::GetTransaction(/*block_index=*/nullptr, mempool, txin.prevout.hash, hashBlock, chainman.m_blockman);
    if (!txPrev) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-coinstake-prev-missing",
            strprintf("CheckProofOfStake() : txPrev %s not found", txin.prevout.hash.ToString()));
    }
    if (txin.prevout.n >= txPrev->vout.size()) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-coinstake-prev-n-out-of-range",
            "CheckProofOfStake() : prevout.n out of range");
    }

    // Verify coinstake signature against the previous output
    PrecomputedTransactionData txdata(*tx);
    static SignatureCache kernel_sigcache{32 * 1024 * 1024};
    CScriptCheck check(txPrev->vout[txin.prevout.n], *tx, kernel_sigcache, /*nIn=*/0, /*nFlags=*/0, /*cache=*/true, &txdata);
    if (auto err = check()) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-coinstake-sig",
            strprintf("CheckProofOfStake() : signature failed on coinstake %s (%s)", tx->GetHash().ToString(), ScriptErrorString(err->first)));
    }

    // Read the block containing the previous transaction to recover its
    // header and the kernel input's offset within the block serialization.
    // Offset definition (consensus): legacy 84-byte header size plus the
    // serialized sizes of the tx-count prefix and all preceding transactions.
    const CBlockIndex* pindexFrom = chainman.m_blockman.LookupBlockIndex(hashBlock);
    if (!pindexFrom) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-coinstake-prev-block-missing",
            "CheckProofOfStake() : prev block index not found");
    }
    CBlock blockFromDisk;
    if (!chainman.m_blockman.ReadBlock(blockFromDisk, *pindexFrom)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-coinstake-prev-block-unreadable",
            "CheckProofOfStake() : prev block not available on disk");
    }
    unsigned int nTxPrevOffset = 0;
    {
        // Offset must match the on-disk encoding: legacy (80-byte) header
        // for pre-fork blocks, full header otherwise; txs with witness.
        SizeComputer ss{};
        ss << VARINT(blockFromDisk.vtx.size());
        bool found = false;
        for (const auto& txInBlock : blockFromDisk.vtx) {
            if (txInBlock->GetHash() == txin.prevout.hash) {
                found = true;
                break;
            }
            ss << TX_WITH_WITNESS(txInBlock);
        }
        if (!found) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-coinstake-prev-not-in-block",
                "CheckProofOfStake() : prev tx not found in its block");
        }
        // Offset rule (BCA-compatible): the txindex offset is measured from
        // after the header, and the kernel always adds the 80-byte legacy
        // header size — for new-format blocks too. Do not "fix" this to 84:
        // it would fork the kernel hash away from BCA history.
        nTxPrevOffset = 80 + ss.size();
    }

    const CBlockIndex* pindexTip = chainman.ActiveTip();
    if (!pindexTip) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-coinstake-no-tip",
            "CheckProofOfStake() : no active tip");
    }
    if (!CheckStakeKernelHash(consensus, pindexTip, nBits, blockFromDisk, nTxPrevOffset, txPrev->vout[txin.prevout.n], txin.prevout, nBlockTime, hashProofOfStake, LogAcceptCategory(BCLog::STAKEMODIFIER, BCLog::Level::Debug)))
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-coinstake-kernel",
            strprintf("CheckProofOfStake() : kernel failed on coinstake %s, hashProof=%s", tx->GetHash().ToString(), hashProofOfStake.ToString()));

    return true;
}

// Get stake modifier checksum
unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex)
{
    assert(pindex->pprev || pindex->nHeight == 0);
    // Hash previous checksum with flags, hashProofOfStake and nStakeModifier
    HashWriter ss{};
    if (pindex->pprev)
        ss << pindex->pprev->nStakeModifierChecksum;
    ss << pindex->nFlags << pindex->hashProofOfStake << pindex->nStakeModifier;
    arith_uint256 hashChecksum = UintToArith256(ss.GetHash());
    hashChecksum >>= (256 - 32);
    return hashChecksum.GetLow64();
}

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, unsigned int nStakeModifierChecksum)
{
    // No checkpoints registered; hook for deterministic testnet/mainnet pins.
    if (mapStakeModifierCheckpoints.count(nHeight))
        return nStakeModifierChecksum == mapStakeModifierCheckpoints[nHeight];
    return true;
}
