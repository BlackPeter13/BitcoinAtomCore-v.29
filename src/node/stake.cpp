// Copyright (c) 2026 The Atom Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Proof-of-stake coinstake creation for legacy wallets.
//
// Ported from Bitcoin Atom (BCA, 0.16-based) to Core 29.x. Notable
// adaptations:
// - Chain access via ChainstateManager (was chainActive/::Params globals).
// - Prev-tx lookup via node::GetTransaction + prev block header, cached per
//   prev-tx (was txindex file offsets; header time equals the Coin::nTime
//   written at confirmation, so the age filter is exact).
// - Signing via ProduceSignature with the wallet's solving provider.
// - The kernel input is signed AFTER fee inputs are final (BCA signed first,
//   which would invalidate the SIGHASH_ALL kernel signature whenever the fee
//   loop added inputs).
#include <wallet/wallet.h>

#include <bitcoin-build-config.h> // IWYU pragma: keep

#ifdef ENABLE_WALLET

#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <hash.h>
#include <index/txindex.h>
#include <kernel/chainparams.h>
#include <key_io.h>
#include <logging.h>
#include <kernel.h>
#include <node/miner.h>
#include <node/transaction.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/solver.h>
#include <serialize.h>
#include <util/moneystr.h>
#include <util/time.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/receive.h>
#include <wallet/spend.h>

namespace wallet {

static const unsigned int MAX_COINSTAKE_INPUTS = 20;
static const int64_t DEFAULT_STAKE_SPLIT_AGE = 30 * 24 * 60 * 60;

struct KernelInput {
    COutPoint prevout;
    CTransactionRef txPrev;
    CBlockHeader headerPrev;
    unsigned int nTxOffset;
    CScript scriptPubKey;
    CScript scriptSign;
    CAmount nValue;
    int64_t nTxTime;
};

bool CWallet::CreateCoinStake(ChainstateManager& chainman, unsigned int nBits, int64_t nSearchInterval, CMutableTransaction& txNew, uint32_t& nCoinStakeTime, CAmount& nPosReward)
{
    AssertLockHeld(cs_wallet);
    const Consensus::Params& consensus = chainman.GetConsensus();
    const CBlockIndex* pindexTip = WITH_LOCK(::cs_main, return chainman.ActiveTip());
    if (!pindexTip) return false;

    const int nHeight = pindexTip->nHeight + 1;
    if (nHeight < consensus.BCAHeight) {
        LogDebug(BCLog::COINSTAKE, "CreateCoinStake: pre-fork, nothing to stake\n");
        return false;
    }
    if (!g_txindex) {
        LogDebug(BCLog::COINSTAKE, "CreateCoinStake: -txindex is required for staking\n");
        return false;
    }

    const CAmount nPoWReward = GetBlockSubsidy(pindexTip->nPowHeight, consensus);
    const int64_t nBalance = GetBalance(*this).m_mine_trusted;
    if (nBalance <= gArgs.GetIntArg("-reservebalance", 0)) return false;

    // Gather kernel candidates: mature, valuable, P2PK(-wrapped) coins.
    std::vector<KernelInput> kernelInputs;
    std::map<uint256, std::tuple<CBlockHeader, unsigned int, CTransactionRef>> mapPrev;
    for (const COutput& out : AvailableCoins(*this).All()) {
        const COutPoint& prevout = out.outpoint;
        auto itPrev = mapPrev.find(prevout.hash);
        if (itPrev == mapPrev.end()) {
            uint256 hashBlock;
            CTransactionRef txPrev = node::GetTransaction(nullptr, nullptr, prevout.hash, hashBlock, chainman.m_blockman);
            if (!txPrev) continue;
            const CBlockIndex* pindexPrev = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(hashBlock));
            if (!pindexPrev) continue;
            CBlock blockPrev;
            if (!chainman.m_blockman.ReadBlock(blockPrev, *pindexPrev)) continue;
            DataStream ssSizes{};
            // BCA kernel-offset rule: always add the 80-byte legacy header
            // size, even for new-format blocks (see kernel.cpp).
            unsigned int nOffset = 80 + (unsigned int)GetSerializeSize(VARINT((uint32_t)blockPrev.vtx.size()));
            unsigned int nMyOffset = 0;
            bool fFound = false;
            for (const auto& tx : blockPrev.vtx) {
                if (tx->GetHash() == prevout.hash) { nMyOffset = nOffset; fFound = true; break; }
                DataStream ss{};
                ss << TX_WITH_WITNESS(tx);
                nOffset += (unsigned int)ss.size();
            }
            if (!fFound) continue;
            itPrev = mapPrev.emplace(prevout.hash, std::make_tuple(blockPrev.GetBlockHeader(), nMyOffset, txPrev)).first;
        }
        const CBlockHeader& hdrPrev = std::get<0>(itPrev->second);
        const CTransactionRef& txPrev = std::get<2>(itPrev->second);
        if (!txPrev || prevout.n >= txPrev->vout.size()) continue;

        const int64_t nBlockTime = hdrPrev.GetBlockTime();
        if (nBlockTime + consensus.nStakeMinAge > (int64_t)nCoinStakeTime) continue;

        const CTxOut& prevTxOut = txPrev->vout[prevout.n];
        if (prevTxOut.nValue < consensus.nStakeMinValue) continue;

        std::vector<std::vector<unsigned char>> vSolutions;
        TxoutType whichType = Solver(prevTxOut.scriptPubKey, vSolutions);
        if (whichType != TxoutType::PUBKEY && whichType != TxoutType::SCRIPTHASH) continue;

        KernelInput input;
        input.prevout = prevout;
        input.txPrev = txPrev;
        input.headerPrev = hdrPrev;
        input.nTxOffset = std::get<1>(itPrev->second);
        input.scriptPubKey = prevTxOut.scriptPubKey;
        input.nValue = prevTxOut.nValue;
        input.nTxTime = nBlockTime;
        if (whichType == TxoutType::PUBKEY) {
            input.scriptSign = CScript() << vSolutions[0] << OP_CHECKSIG;
        } else {
            CScript subscript;
            if (!GetSolvingProvider(input.scriptPubKey)->GetCScript(CScriptID(uint160(vSolutions[0])), subscript)) continue;
            std::vector<std::vector<unsigned char>> vSubSolutions;
            if (Solver(subscript, vSubSolutions) != TxoutType::PUBKEY || vSubSolutions.empty()) continue;
            input.scriptSign = subscript;
        }
        kernelInputs.push_back(std::move(input));
    }
    if (kernelInputs.empty()) return false;

    // Oldest-first, like BCA.
    std::sort(kernelInputs.begin(), kernelInputs.end(),
              [](const KernelInput& a, const KernelInput& b) { return a.nTxTime < b.nTxTime; });

    // Preselect small inputs to combine into the kernel.
    const CAmount nCombineThreshold = gArgs.GetIntArg("-coinstakeinputlimit", 50 * COIN) / COIN;
    std::vector<KernelInput*> vPreselected;
    CAmount nPreselectedValue = 0;
    for (auto& input : kernelInputs) {
        if (nPreselectedValue >= nCombineThreshold) break;
        if (vPreselected.size() >= MAX_COINSTAKE_INPUTS) break;
        vPreselected.push_back(&input);
        nPreselectedValue += input.nValue;
    }
    if (vPreselected.empty()) return false;

    // Search for a kernel over the interval.
    const KernelInput* pKernel = nullptr;
    FastRandomContext insecure_rand;
    const int64_t nCurrentTime = TicksSinceEpoch<std::chrono::seconds>(NodeClock::now());
    for (int64_t n = 0; n <= nSearchInterval && nCurrentTime - n >= pindexTip->GetBlockTime(); ++n, --nCoinStakeTime) {
        for (auto* pInput : vPreselected) {
            uint256 hashProofOfStake;
            if (!CheckStakeKernelHash(consensus, pindexTip, nBits, pInput->headerPrev,
                                      pInput->nTxOffset, pInput->txPrev->vout[pInput->prevout.n], pInput->prevout,
                                      nCoinStakeTime, hashProofOfStake)) {
                continue;
            }
            // Even spread: skip randomly unless this is the only candidate.
            if (vPreselected.size() > 1 && insecure_rand.randrange((int)vPreselected.size()) != 0) continue;
            pKernel = pInput;
            break;
        }
        if (pKernel) break;
        // Also try non-preselected candidates.
        for (auto& input : kernelInputs) {
            uint256 hashProofOfStake;
            if (!CheckStakeKernelHash(consensus, pindexTip, nBits, input.headerPrev,
                                      input.nTxOffset, input.txPrev->vout[input.prevout.n], input.prevout,
                                      nCoinStakeTime, hashProofOfStake)) {
                continue;
            }
            pKernel = &input;
            break;
        }
        if (pKernel) break;
    }
    if (!pKernel) return false;
    LogDebug(BCLog::COINSTAKE, "CreateCoinStake: kernel found value=%s time=%u\n",
             FormatMoney(pKernel->nValue), nCoinStakeTime);

    // Assemble inputs: kernel first, then preselected, then fee top-ups.
    txNew.vin.clear();
    txNew.vin.emplace_back(pKernel->prevout);
    CAmount nValueIn = pKernel->nValue;
    for (auto* pInput : vPreselected) {
        if (pInput->prevout == pKernel->prevout) continue;
        if (txNew.vin.size() >= MAX_COINSTAKE_INPUTS) break;
        txNew.vin.emplace_back(pInput->prevout);
        nValueIn += pInput->nValue;
    }

    CFeeRate minFeeRate{DEFAULT_TRANSACTION_MINFEE};
    CAmount nMinFee = minFeeRate.GetFee(GetSerializeSize(TX_WITH_WITNESS(txNew)));
    for (auto& input : kernelInputs) {
        if (nValueIn >= nPoWReward + nMinFee || txNew.vin.size() >= MAX_COINSTAKE_INPUTS) break;
        bool fHave = false;
        for (const auto& vin : txNew.vin) {
            if (vin.prevout == input.prevout) { fHave = true; break; }
        }
        if (fHave) continue;
        txNew.vin.emplace_back(input.prevout);
        nValueIn += input.nValue;
        nMinFee = minFeeRate.GetFee(GetSerializeSize(TX_WITH_WITNESS(txNew)));
    }

    // Reward from the age of all selected inputs.
    uint64_t nCoinAge = 0;
    {
        CTransaction txConst(txNew);
        if (!GetCoinAge(chainman, txConst, nCoinAge, nCoinStakeTime)) {
            LogError("%s: failed to calculate coin age\n", __func__);
            return false;
        }
    }
    nPosReward = GetProofOfStakeReward((int64_t)nCoinAge);

    // Outputs: marker (value set by the miner) + optional split output.
    txNew.vout.clear();
    txNew.vout.emplace_back(CTxOut(0, CScript()));
    const uint64_t nStakeAge = (uint64_t)nCoinStakeTime - (uint64_t)pKernel->nTxTime;
    if (gArgs.GetBoolArg("-splitpos", true) &&
        nStakeAge > (uint64_t)gArgs.GetIntArg("-stakesplitage", DEFAULT_STAKE_SPLIT_AGE)) {
        txNew.vout.emplace_back(CTxOut(0, CScript()));
    }

    // Split the change between outputs (except the marker).
    CAmount nChange = nValueIn - (nPoWReward + nMinFee);
    if (nChange < 0 || !MoneyRange(nValueIn)) {
        LogError("%s: inputs do not cover reward+fee\n", __func__);
        return false;
    }
    const size_t nOuts = txNew.vout.size();
    for (size_t i = 1; i < nOuts; i++) {
        txNew.vout[i].nValue = nChange / (nOuts - 1);
    }

    // Sign the kernel input LAST (SIGHASH_ALL commits to all inputs/outputs).
    {
        auto provider = GetSolvingProvider(pKernel->scriptPubKey);
        SignatureData sigdata;
        if (!ProduceSignature(*provider,
                              MutableTransactionSignatureCreator(txNew, 0, pKernel->nValue, SIGHASH_ALL | SIGHASH_FORKID),
                              pKernel->scriptSign, sigdata)) {
            return false;
        }
        UpdateInput(txNew.vin[0], sigdata);
        if (!sigdata.complete || txNew.vin[0].scriptSig.size() >= 1650) {
            LogError("%s: kernel signing failed\n", __func__);
            return false;
        }
    }

    if (GetSerializeSize(TX_WITH_WITNESS(txNew)) >= (size_t)MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR) {
        LogError("%s: coinstake too large\n", __func__);
        return false;
    }

    node::nLastCoinStakeSearchInterval = nSearchInterval + 1;
    LogDebug(BCLog::COINSTAKE, "CreateCoinStake: success reward=%s inputs=%u age=%lu\n",
             FormatMoney(nPosReward), (unsigned int)txNew.vin.size(), (unsigned long)nCoinAge);
    return true;
}

} // namespace wallet

#endif // ENABLE_WALLET