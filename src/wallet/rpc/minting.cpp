// Copyright (c) 2026 The Atom Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// listminting RPC: mintable outputs with coin age and minting probabilities.
// Ported from Bitcoin Atom to Core 29.x wallet RPCs.
#include <wallet/rpc/minting.h>

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <key_io.h>
#include <node/context.h>
#include <node/miner.h>
#include <node/transaction.h>
#include <pow.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <util/moneystr.h>
#include <util/time.h>
#include <validation.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

namespace wallet {
namespace {

const int DAY = 24 * 60 * 60;

int64_t NowSecs()
{
    return TicksSinceEpoch<std::chrono::seconds>(NodeClock::now());
}

class KernelRecord
{
public:
    Txid hash;
    int64_t nTime{0};
    std::string address;
    CAmount nValue{0};
    int vout{0};
    bool spent{false};
    uint64_t coinAge{0};

    KernelRecord() = default;
    KernelRecord(Txid h, int64_t t) : hash(h), nTime(t) {}
    KernelRecord(Txid h, int64_t t, const std::string& addr, CAmount val, int idx, bool sp, uint64_t age)
        : hash(h), nTime(t), address(addr), nValue(val), vout(idx), spent(sp), coinAge(age) {}

    static bool ShowTransaction(const CWallet& wallet, const CWalletTx& wtx)
    {
        const int nDepth = wallet.GetTxDepthInMainChain(wtx);
        if (wtx.IsCoinBase()) {
            if (nDepth < 2) return false;
        } else if (nDepth == 0) {
            return false;
        }
        return true;
    }

    static std::vector<KernelRecord> DecomposeOutputs(const CWallet& wallet, ChainstateManager& chainman, const CWalletTx& wtx)
    {
        std::vector<KernelRecord> kernels;
        int64_t nTime = 0;
        const Txid hash = wtx.GetHash();

        uint256 hashBlock;
        CTransactionRef txTmp = node::GetTransaction(nullptr, nullptr, hash, hashBlock, chainman.m_blockman);
        if (txTmp) {
            const CBlockIndex* pindex = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(hashBlock));
            if (pindex) nTime = pindex->GetBlockTime();
        }

        const Consensus::Params& consensus = chainman.GetConsensus();
        const int64_t nDayWeight = (std::min(NowSecs() - nTime, consensus.nStakeMaxAge) - consensus.nStakeMinAge) / DAY;

        if (ShowTransaction(wallet, wtx) && wtx.tx) {
            for (size_t nOut = 0; nOut < wtx.tx->vout.size(); nOut++) {
                const CTxOut& txOut = wtx.tx->vout[nOut];
                if (wallet.IsMine(txOut)) {
                    CTxDestination address;
                    std::string addrStr;
                    if (ExtractDestination(txOut.scriptPubKey, address)) {
                        addrStr = EncodeDestination(address);
                    }
                    const uint64_t coinAge = (uint64_t)std::max(txOut.nValue * nDayWeight / COIN, (int64_t)0);
                    kernels.emplace_back(hash, nTime, addrStr, txOut.nValue, (int)nOut,
                                         wallet.IsSpent(COutPoint(hash, (uint32_t)nOut)), coinAge);
                }
            }
        }
        return kernels;
    }

    int64_t GetAge() const { return (NowSecs() - nTime) / DAY; }

    double CalcMintingProbability(uint32_t nBits, int timeOffset, int64_t stakeMinAge, int64_t stakeMaxAge) const
    {
        const int64_t nTimeWeight = std::min((NowSecs() - nTime) + timeOffset, stakeMaxAge) - stakeMinAge;
        const arith_uint256 bnCoinDayWeight = arith_uint256(nValue) * nTimeWeight / COIN / DAY;
        arith_uint256 bnTargetPerCoinDay;
        bnTargetPerCoinDay.SetCompact(nBits);
        const double targetLimit = (~arith_uint256(0)).getdouble();
        return (bnCoinDayWeight * bnTargetPerCoinDay).getdouble() / targetLimit;
    }

    double CalculateMintingProbabilityWithinPeriod(uint32_t nBits, int minutes, int64_t stakeMinAge, int64_t stakeMaxAge) const
    {
        double prob = 1;
        const int d = minutes / (60 * 24);
        const int m = minutes % (60 * 24);
        int timeOffset = DAY;
        for (int i = 0; i < d; i++, timeOffset += DAY) {
            prob *= pow(1 - CalcMintingProbability(nBits, timeOffset, stakeMinAge, stakeMaxAge), DAY);
        }
        prob *= pow(1 - CalcMintingProbability(nBits, timeOffset, stakeMinAge, stakeMaxAge), 60 * m);
        return 1 - prob;
    }
};

} // namespace

RPCHelpMan listminting()
{
    return RPCHelpMan{"listminting",
        "\nReturn all mintable outputs and provide details for each of them.\n",
        {
            {"count", RPCArg::Type::NUM, RPCArg::Default{0}, "The number of outputs to return (0 - all)"},
            {"skip", RPCArg::Type::NUM, RPCArg::Default{0}, "The number of outputs to skip"},
            {"minweight", RPCArg::Type::NUM, RPCArg::Default{0}, "Min output weight"},
            {"maxweight", RPCArg::Type::NUM, RPCArg::Default{0}, "Max output weight (0 - unlimited)"},
        },
        RPCResult{RPCResult::Type::ARR, "", "", {
            {RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR, "account", "Account name if the address is in the address book"},
                {RPCResult::Type::STR, "address", "The address holding the mintable output"},
                {RPCResult::Type::STR_HEX, "txid", "The output's transaction id"},
                {RPCResult::Type::NUM, "vout", "The output index"},
                {RPCResult::Type::NUM_TIME, "time", "The output's block time"},
                {RPCResult::Type::STR_AMOUNT, "amount", "The output value"},
                {RPCResult::Type::STR, "status", "immature or mature"},
                {RPCResult::Type::NUM, "age-in-day", "Output age in days"},
                {RPCResult::Type::NUM, "coin-day-weight", "Coin-day weight"},
                {RPCResult::Type::NUM, "minting-probability-10min", "Minting probability within 10 minutes"},
                {RPCResult::Type::NUM, "minting-probability-24h", "Minting probability within 24 hours"},
                {RPCResult::Type::NUM, "minting-probability-30d", "Minting probability within 30 days"},
                {RPCResult::Type::NUM, "minting-probability-90d", "Minting probability within 90 days"},
                {RPCResult::Type::NUM, "attempts", "Seconds the output has been staking-eligible"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("listminting", "")
            + HelpExampleRpc("listminting", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "No wallet loaded");
    }
    const CWallet* pwallet = wallet.get();
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = *Assert(node.chainman);

    const int64_t nCount = request.params[0].isNull() ? 0 : request.params[0].getInt<int64_t>();
    int64_t nSkip = request.params[1].isNull() ? 0 : request.params[1].getInt<int64_t>();
    const uint64_t nMinWeight = request.params[2].isNull() ? 0 : (uint64_t)request.params[2].getInt<int64_t>();
    const uint64_t nMaxWeight = request.params[3].isNull() ? 0 : (uint64_t)request.params[3].getInt<int64_t>();
    if (nCount < 0 || nSkip < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count/skip");
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    const Consensus::Params& consensus = chainman.GetConsensus();
    const CBlockIndex* tip = WITH_LOCK(::cs_main, return chainman.ActiveTip());
    const CBlockIndex* p = GetLastBlockIndex(tip, consensus, /*fProofOfStake=*/true);
    const uint32_t nBits = (p == nullptr) ? UintToArith256(consensus.nInitialHashTargetPoS).GetCompact() : p->nBits;

    UniValue ret(UniValue::VARR);
    const int minAge = (int)(consensus.nStakeMinAge / DAY);

    for (const auto& [txid, wtx] : pwallet->mapWallet) {
        for (KernelRecord& kr : KernelRecord::DecomposeOutputs(*pwallet, chainman, wtx)) {
            if (kr.coinAge < nMinWeight) continue;
            if (nMaxWeight != 0 && kr.coinAge > nMaxWeight) continue;
            if (nSkip != 0) { --nSkip; continue; }
            if (nCount != 0 && ret.size() >= (size_t)nCount) break;

            std::string account;
            const CTxDestination dest = DecodeDestination(kr.address);
            auto mi = pwallet->m_address_book.find(dest);
            if (mi != pwallet->m_address_book.end()) {
                account = mi->second.GetLabel();
            }

            std::string status = "immature";
            int attempts = 0;
            if (kr.GetAge() >= minAge) {
                status = "mature";
                attempts = (int)(NowSecs() - kr.nTime - consensus.nStakeMinAge);
            }

            UniValue obj(UniValue::VOBJ);
            obj.pushKV("account", account);
            obj.pushKV("address", kr.address);
            obj.pushKV("txid", kr.hash.GetHex());
            obj.pushKV("vout", kr.vout);
            obj.pushKV("time", kr.nTime);
            obj.pushKV("amount", ValueFromAmount(kr.nValue));
            obj.pushKV("status", status);
            obj.pushKV("age-in-day", kr.GetAge());
            obj.pushKV("coin-day-weight", kr.coinAge);
            obj.pushKV("minting-probability-10min", kr.CalculateMintingProbabilityWithinPeriod(nBits, 10, consensus.nStakeMinAge, consensus.nStakeMaxAge));
            obj.pushKV("minting-probability-24h", kr.CalculateMintingProbabilityWithinPeriod(nBits, 60 * 24, consensus.nStakeMinAge, consensus.nStakeMaxAge));
            obj.pushKV("minting-probability-30d", kr.CalculateMintingProbabilityWithinPeriod(nBits, 60 * 24 * 30, consensus.nStakeMinAge, consensus.nStakeMaxAge));
            obj.pushKV("minting-probability-90d", kr.CalculateMintingProbabilityWithinPeriod(nBits, 60 * 24 * 90, consensus.nStakeMinAge, consensus.nStakeMaxAge));
            obj.pushKV("attempts", attempts);
            ret.push_back(obj);
        }
        if (nCount != 0 && ret.size() >= (size_t)nCount) break;
    }
    return ret;
},
    };
}

RPCHelpMan startstaking()
{
    return RPCHelpMan{"startstaking",
        "\nRegister this wallet for background proof-of-stake minting. The node mints PoS blocks while the wallet is unlocked (mint-only unlocks stake but cannot spend).\n",
        {},
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{
            HelpExampleCli("startstaking", "")
            + HelpExampleRpc("startstaking", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "No wallet loaded");
    }
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    node::RegisterStakingWallet(wallet);
    node::StartStakingThread(node);
    return UniValue::VNULL;
},
    };
}

RPCHelpMan stopstaking()
{
    return RPCHelpMan{"stopstaking",
        "\nStop background proof-of-stake minting for this wallet.\n",
        {},
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{
            HelpExampleCli("stopstaking", "")
            + HelpExampleRpc("stopstaking", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "No wallet loaded");
    }
    node::UnregisterStakingWallet(wallet.get());
    return UniValue::VNULL;
},
    };
}

} // namespace wallet
