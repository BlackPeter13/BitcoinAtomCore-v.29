// Copyright (c) 2026 The Atom Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Atomic-swap (HTLC) RPCs, ported from Bitcoin Atom to Core 29.x wallet RPCs.
#include <wallet/rpc/swap.h>

#include <consensus/amount.h>
#include <core_io.h>
#include <crypto/sha256.h>
#include <key_io.h>
#include <node/types.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <random.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <serialize.h>
#include <span.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/rpc/util.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wallet {
namespace {

const int SECRET_SIZE = 32;

struct SwapContract {
    CScript contractRedeemscript;
    CScriptID contractAddr;
    CAmount contractFee{0};
    CTransactionRef contactTx;
    CTransactionRef refundTx;
    CAmount refundFee{0};
};

const int redeemAtomicSwapSigScriptSize = 1 + 73 + 1 + 33 + 1 + 32 + 1;
const int refundAtomicSwapSigScriptSize = 1 + 73 + 1 + 33 + 1;

int CalcInputSize(int scriptSigSize)
{
    return 32 + 4 + GetSerializeSize(COMPACTSIZE((uint64_t)scriptSigSize)) + scriptSigSize + 4;
}

int EstimateRefundTxSerializeSize(const CScript& contractRedeemscript, const std::vector<CTxOut>& txOuts)
{
    int outputsSerializeSize = 0;
    for (const CTxOut& txout : txOuts) {
        outputsSerializeSize += GetSerializeSize(txout);
    }
    return 4 + 4 + 4 + GetSerializeSize(COMPACTSIZE((uint64_t)1)) + GetSerializeSize(COMPACTSIZE(txOuts.size())) + CalcInputSize(refundAtomicSwapSigScriptSize + contractRedeemscript.size()) + outputsSerializeSize;
}

int EstimateRedeemTxSerializeSize(const CScript& contractRedeemscript, const std::vector<CTxOut>& txOuts)
{
    int outputsSerializeSize = 0;
    for (const CTxOut& txout : txOuts) {
        outputsSerializeSize += GetSerializeSize(txout);
    }
    return 4 + 4 + 4 + GetSerializeSize(COMPACTSIZE((uint64_t)1)) + GetSerializeSize(COMPACTSIZE(txOuts.size())) + CalcInputSize(redeemAtomicSwapSigScriptSize + contractRedeemscript.size()) + outputsSerializeSize;
}

bool TryDecodeAtomicSwapScript(const CScript& contractRedeemscript,
                               std::vector<unsigned char>& secretHash, CKeyID& recipient, CKeyID& refund, int64_t& locktime, int64_t& secretSize)
{
    CScript::const_iterator pc = contractRedeemscript.begin();
    opcodetype opcode;
    std::vector<unsigned char> secretSizeData;
    std::vector<unsigned char> locktimeData;
    std::vector<unsigned char> recipientHash;
    std::vector<unsigned char> refundHash;

    if ((contractRedeemscript.GetOp(pc, opcode) && opcode == OP_IF) &&
        (contractRedeemscript.GetOp(pc, opcode) && opcode == OP_SIZE) &&
        (contractRedeemscript.GetOp(pc, opcode, secretSizeData)) &&
        (contractRedeemscript.GetOp(pc, opcode) && opcode == OP_EQUALVERIFY) &&
        (contractRedeemscript.GetOp(pc, opcode) && opcode == OP_SHA256) &&
        (contractRedeemscript.GetOp(pc, opcode, secretHash) && opcode == 0x20) &&
        (contractRedeemscript.GetOp(pc, opcode) && opcode == OP_EQUALVERIFY) &&
        (contractRedeemscript.GetOp(pc, opcode) && opcode == OP_DUP) &&
        (contractRedeemscript.GetOp(pc, opcode) && opcode == OP_HASH160) &&
        (contractRedeemscript.GetOp(pc, opcode, recipientHash) && opcode == 0x14) &&
        (contractRedeemscript.GetOp(pc, opcode) && opcode == OP_ELSE) &&
        (contractRedeemscript.GetOp(pc, opcode, locktimeData)) &&
        (contractRedeemscript.GetOp(pc, opcode) && opcode == OP_CHECKLOCKTIMEVERIFY) &&
        (contractRedeemscript.GetOp(pc, opcode) && opcode == OP_DROP) &&
        (contractRedeemscript.GetOp(pc, opcode) && opcode == OP_DUP) &&
        (contractRedeemscript.GetOp(pc, opcode) && opcode == OP_HASH160) &&
        (contractRedeemscript.GetOp(pc, opcode, refundHash) && opcode == 0x14) &&
        (contractRedeemscript.GetOp(pc, opcode) && opcode == OP_ENDIF) &&
        (contractRedeemscript.GetOp(pc, opcode) && opcode == OP_EQUALVERIFY) &&
        (contractRedeemscript.GetOp(pc, opcode) && opcode == OP_CHECKSIG)
        ) {
        secretSize = CScriptNum(secretSizeData, true).getint();
        locktime = CScriptNum(locktimeData, true).getint();
        recipient = CKeyID(uint160(recipientHash));
        refund = CKeyID(uint160(refundHash));
        return true;
    }

    return false;
}

CScript CreateAtomicSwapRedeemscript(const CKeyID& initiator, const CKeyID& redeemer, int64_t locktime, int64_t secretSize, const std::vector<unsigned char>& secretHash)
{
    CScript redeemScript;
    redeemScript << OP_IF << OP_SIZE << secretSize << OP_EQUALVERIFY << OP_SHA256
                 << ToByteVector(secretHash) << OP_EQUALVERIFY << OP_DUP << OP_HASH160
                 << ToByteVector(redeemer) << OP_ELSE << locktime << OP_CHECKLOCKTIMEVERIFY
                 << OP_DROP << OP_DUP << OP_HASH160 << ToByteVector(initiator)
                 << OP_ENDIF << OP_EQUALVERIFY << OP_CHECKSIG;
    return redeemScript;
}

// Sign a swap (refund or redeem) input with the wallet key.
bool SignSwapInput(CWallet* pwallet, const CScript& contractRedeemscript, const CScript& contractPubKeyScript,
                   const CKeyID& keyid, const std::vector<unsigned char>& secret, bool fRedeem,
                   CMutableTransaction& tx, CAmount amount, CScript& sigScript)
{
    auto key = pwallet->GetKey(keyid);
    if (!key) return false;
    const uint256 sighash = SignatureHash(contractRedeemscript, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, amount, SigVersion::BASE);
    std::vector<unsigned char> vchSig;
    if (!key->Sign(sighash, vchSig)) return false;
    vchSig.push_back((unsigned char)(SIGHASH_ALL | SIGHASH_FORKID));
    const CPubKey pubKey = key->GetPubKey();
    if (fRedeem) {
        sigScript = CScript() << vchSig << ToByteVector(pubKey) << secret << int64_t(1)
                              << std::vector<unsigned char>(contractRedeemscript.begin(), contractRedeemscript.end());
    } else {
        sigScript = CScript() << vchSig << ToByteVector(pubKey) << int64_t(0)
                              << std::vector<unsigned char>(contractRedeemscript.begin(), contractRedeemscript.end());
    }
    MutableTransactionSignatureChecker checker(&tx, 0, amount, MissingDataBehavior::FAIL);
    return VerifyScript(sigScript, contractPubKeyScript, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, checker);
}

void BuildRefundTransaction(CWallet* pwallet, const CScript& contractRedeemscript, const CMutableTransaction& contractTx, CMutableTransaction& refundTx, CAmount& refundFee)
{
    std::vector<unsigned char> secretHash;
    CKeyID recipient;
    CKeyID refundAddr;
    int64_t locktime;
    int64_t secretSize;

    if (!TryDecodeAtomicSwapScript(contractRedeemscript, secretHash, recipient, refundAddr, locktime, secretSize)) {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Invalid atomic swap script");
    }

    const CScriptID swapContractAddr(contractRedeemscript);
    const CScript contractPubKeyScript = GetScriptForDestination(ScriptHash(swapContractAddr));

    COutPoint contractOutPoint;
    contractOutPoint.n = (uint32_t)-1;
    for (size_t i = 0; i < contractTx.vout.size(); i++) {
        if (contractTx.vout[i].scriptPubKey == contractPubKeyScript) {
            contractOutPoint = COutPoint(contractTx.GetHash(), (uint32_t)i);
            break;
        }
    }
    if (contractOutPoint.n == (uint32_t)-1) {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Contract tx does not contain a P2SH contract payment");
    }

    auto change = pwallet->GetNewChangeDestination(OutputType::LEGACY);
    if (!change) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(change).original);
    }
    const CScript refundPubkeyScript = GetScriptForDestination(change.value());

    refundTx.nLockTime = (uint32_t)locktime;
    refundTx.vout.emplace_back(0, refundPubkeyScript);

    const int refundTxSize = EstimateRefundTxSerializeSize(contractRedeemscript, refundTx.vout);
    const CCoinControl coinControl;
    refundFee = GetMinimumFee(*pwallet, refundTxSize, coinControl, nullptr);
    refundTx.vout[0].nValue = contractTx.vout[contractOutPoint.n].nValue - refundFee;
    if (IsDust(refundTx.vout[0], GetDiscardRate(*pwallet))) {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, strprintf("Refund output value of %d is dust", refundTx.vout[0].nValue));
    }

    CTxIn txIn(contractOutPoint);
    txIn.nSequence = 0;
    refundTx.vin.push_back(txIn);

    CScript refundSigScript;
    if (!SignSwapInput(pwallet, contractRedeemscript, contractPubKeyScript, refundAddr, {}, false,
                       refundTx, contractTx.vout[contractOutPoint.n].nValue, refundSigScript)) {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Failed to create refund script signature");
    }
    refundTx.vin[0].scriptSig = refundSigScript;
}

void BuildContract(SwapContract& contract, CWallet* pwallet, const CKeyID& dest, CAmount nAmount, int64_t locktime, const std::vector<unsigned char>& secretHash)
{
    LOCK2(cs_main, pwallet->cs_wallet);

    auto change = pwallet->GetNewChangeDestination(OutputType::LEGACY);
    if (!change) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(change).original);
    }
    const CKeyID refundAddress = ToKeyID(std::get<PKHash>(change.value()));

    const CScript contractRedeemscript = CreateAtomicSwapRedeemscript(refundAddress, dest, locktime, SECRET_SIZE, secretHash);
    const CScriptID swapContractAddr(contractRedeemscript);

    std::vector<CRecipient> vecSend;
    vecSend.push_back({ScriptHash(swapContractAddr), nAmount, false});
    CCoinControl coinControl;
    coinControl.m_change_type = OutputType::LEGACY;
    auto res = CreateTransaction(*pwallet, vecSend, /*change_pos=*/std::nullopt, coinControl, /*sign=*/true);
    if (!res) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(res).original);
    }

    CMutableTransaction refundTx;
    CAmount refundFee;
    BuildRefundTransaction(pwallet, contractRedeemscript, CMutableTransaction(*res.value().tx), refundTx, refundFee);

    contract.contractRedeemscript = contractRedeemscript;
    contract.contractAddr = swapContractAddr;
    contract.contactTx = res.value().tx;
    contract.contractFee = res.value().fee;
    contract.refundTx = MakeTransactionRef(std::move(refundTx));
    contract.refundFee = refundFee;
}

void GenerateSecret(std::vector<unsigned char>& secret, std::vector<unsigned char>& secretHash)
{
    secret.assign(SECRET_SIZE, 0);
    secretHash.assign(CSHA256::OUTPUT_SIZE, 0);

    GetRandBytes(secret);
    CSHA256 sha;
    sha.Write(secret.data(), secret.size());
    sha.Finalize(secretHash.data());
}

UniValue SwapTxToUniv(const CTransactionRef& tx)
{
    UniValue res(UniValue::VOBJ);
    res.pushKV("txid", tx->GetHash().GetHex());
    res.pushKV("hex", EncodeHexTx(*tx));
    return res;
}

void SwapContractToUniv(const SwapContract& contract, UniValue& res)
{
    UniValue c(UniValue::VOBJ);
    c.pushKV("address", EncodeDestination(ScriptHash(contract.contractAddr)));
    c.pushKV("scriptHex", HexStr(contract.contractRedeemscript));
    res.pushKV("contract", c);

    UniValue contractData = SwapTxToUniv(contract.contactTx);
    contractData.pushKV("fee", ValueFromAmount(contract.contractFee));
    res.pushKV("contractTx", contractData);

    UniValue refundData = SwapTxToUniv(contract.refundTx);
    refundData.pushKV("fee", ValueFromAmount(contract.refundFee));
    res.pushKV("refundTx", refundData);
}

int64_t SwapLockTime(int64_t seconds_from_now)
{
    return TicksSinceEpoch<std::chrono::seconds>(NodeClock::now()) + seconds_from_now;
}

const PKHash& RequireP2PKH(const CTxDestination& dest, const char* what)
{
    const PKHash* pk = std::get_if<PKHash>(&dest);
    if (!pk) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("%s address is not P2PKH", what));
    }
    return *pk;
}

} // namespace

RPCHelpMan initiateswap()
{
    return RPCHelpMan{"initiateswap",
        "\nThe initiateswap command is performed by the initiator to create the first contract.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The recipient address (P2PKH)"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The value for the swap"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "secret", "The hex-encoded secret for redemption"},
            {RPCResult::Type::STR_HEX, "secretHash", "The hex-encoded hash of redemption secret"},
            {RPCResult::Type::OBJ, "contract", "The contract for swap", {
                {RPCResult::Type::STR, "address", "The Atom address of the swap contract"},
                {RPCResult::Type::STR_HEX, "scriptHex", "The contract hex script"},
            }},
            {RPCResult::Type::OBJ, "contractTx", "The contract transaction", {
                {RPCResult::Type::STR_HEX, "txid", "The contract transaction id"},
                {RPCResult::Type::STR_HEX, "hex", "The hex-encoded raw transaction with signature(s)"},
                {RPCResult::Type::STR_AMOUNT, "fee", "The contract transaction fee"},
            }},
            {RPCResult::Type::OBJ, "refundTx", "The transaction for refund", {
                {RPCResult::Type::STR_HEX, "txid", "The refund transaction id"},
                {RPCResult::Type::STR_HEX, "hex", "The hex-encoded refund transaction with signature(s)"},
                {RPCResult::Type::STR_AMOUNT, "fee", "The refund transaction fee"},
            }},
        }},
        RPCExamples{
            HelpExampleCli("initiateswap", "\"address\" 1")
            + HelpExampleRpc("initiateswap", "\"address\", 1")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "No wallet loaded");
    }
    CWallet* const pwallet = wallet.get();

    const CKeyID destAddress = ToKeyID(RequireP2PKH(DecodeDestination(request.params[0].get_str()), "Participant"));
    const CAmount nAmount = AmountFromValue(request.params[1]);
    if (nAmount <= 0) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    }

    EnsureWalletIsUnlocked(*pwallet);

    const int64_t locktime = SwapLockTime(48 * 60 * 60);
    std::vector<unsigned char> secret, secretHash;
    GenerateSecret(secret, secretHash);

    SwapContract contract;
    BuildContract(contract, pwallet, destAddress, nAmount, locktime, secretHash);

    UniValue res(UniValue::VOBJ);
    res.pushKV("secret", HexStr(secret));
    res.pushKV("secretHash", HexStr(secretHash));
    SwapContractToUniv(contract, res);
    return res;
},
    };
}

RPCHelpMan participateswap()
{
    return RPCHelpMan{"participateswap",
        "\nThe participateswap command is performed by the participant to create a contract on the second blockchain (24h locktime). Requires the secret hash from the initiator's contract.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The recipient address (P2PKH)"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The value for the swap"},
            {"secrethash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded hash of redemption secret"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Like initiateswap but without the secret"},
        RPCExamples{
            HelpExampleCli("participateswap", "\"address\" 2 \"secrethash\"")
            + HelpExampleRpc("participateswap", "\"address\", 2, \"secrethash\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "No wallet loaded");
    }
    CWallet* const pwallet = wallet.get();

    const CKeyID destAddress = ToKeyID(RequireP2PKH(DecodeDestination(request.params[0].get_str()), "Participant"));
    const CAmount nAmount = AmountFromValue(request.params[1]);
    if (nAmount <= 0) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    }
    std::vector<unsigned char> secretHash(ParseHexV(request.params[2], "secrethash"));
    if (secretHash.size() != CSHA256::OUTPUT_SIZE) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Secret hash has wrong size");
    }

    EnsureWalletIsUnlocked(*pwallet);

    const int64_t locktime = SwapLockTime(24 * 60 * 60);

    SwapContract contract;
    BuildContract(contract, pwallet, destAddress, nAmount, locktime, secretHash);

    UniValue res(UniValue::VOBJ);
    SwapContractToUniv(contract, res);
    return res;
},
    };
}

int FindContractOutput(const CMutableTransaction& tx, const CScriptID& contractAddr)
{
    for (size_t i = 0; i < tx.vout.size(); i++) {
        if (!tx.vout[i].scriptPubKey.IsPayToScriptHash()) continue;
        CTxDestination dest;
        if (!ExtractDestination(tx.vout[i].scriptPubKey, dest)) continue;
        if (const ScriptHash* scriptid = std::get_if<ScriptHash>(&dest)) {
            if (*scriptid == ScriptHash(contractAddr)) return (int)i;
        }
    }
    return -1;
}

RPCHelpMan auditswap()
{
    return RPCHelpMan{"auditswap",
        "\nInspect a contract script and the contract transaction: parses out the claimant/refund addresses, locktime and secret hash, and validates that the transaction pays the contract.\n",
        {
            {"hexscript", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded contract"},
            {"hextransaction", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded contract transaction"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "contractAddress", "The Atom address of the swap contract"},
            {RPCResult::Type::STR_AMOUNT, "contractValue", "The value for the swap"},
            {RPCResult::Type::STR, "recipientAddress", "The recipient address"},
            {RPCResult::Type::STR, "refundAddress", "The address for refund"},
            {RPCResult::Type::STR_HEX, "secretHash", "The hash of redemption secret"},
            {RPCResult::Type::NUM, "locktime", "The time for refund unlock"},
        }},
        RPCExamples{
            HelpExampleCli("auditswap", "\"hexscript\" \"hextransaction\"")
            + HelpExampleRpc("auditswap", "\"hexscript\", \"hextransaction\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::vector<unsigned char> scriptData(ParseHexV(request.params[0], "hexscript"));
    const CScript contractRedeemscript(scriptData.begin(), scriptData.end());

    CMutableTransaction tx;
    if (!DecodeHexTx(tx, request.params[1].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Failed to decode contract transaction");
    }

    const CScriptID contractAddr(contractRedeemscript);
    const int contractOutIndex = FindContractOutput(tx, contractAddr);
    if (contractOutIndex == -1) {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Transaction does not contain the contract output");
    }

    std::vector<unsigned char> secretHash;
    CKeyID recipient;
    CKeyID refundAddr;
    int64_t locktime;
    int64_t secretSize;
    if (!TryDecodeAtomicSwapScript(contractRedeemscript, secretHash, recipient, refundAddr, locktime, secretSize)) {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Invalid atomic swap script");
    }
    if (secretSize != SECRET_SIZE) {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, strprintf("Incorrect secret size: %d", secretSize));
    }

    UniValue res(UniValue::VOBJ);
    res.pushKV("contractAddress", EncodeDestination(ScriptHash(contractAddr)));
    res.pushKV("contractValue", ValueFromAmount(tx.vout[contractOutIndex].nValue));
    res.pushKV("recipientAddress", EncodeDestination(PKHash(recipient)));
    res.pushKV("refundAddress", EncodeDestination(PKHash(refundAddr)));
    res.pushKV("secretHash", HexStr(secretHash));
    res.pushKV("locktime", locktime);
    return res;
},
    };
}

RPCHelpMan redeemswap()
{
    return RPCHelpMan{"redeemswap",
        "\nRedeem coins paid into the other party's contract. Requires the secret; the initiator redeems first, then the participant extracts the secret from the redemption transaction.\n",
        {
            {"hexscript", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded contract"},
            {"hextransaction", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded contract transaction"},
            {"secret", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded secret for redemption"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "txid", "The redemption transaction id"},
            {RPCResult::Type::STR_HEX, "hex", "The hex-encoded redemption transaction"},
            {RPCResult::Type::STR_AMOUNT, "Redeem fee", "The redeem transaction fee"},
        }},
        RPCExamples{
            HelpExampleCli("redeemswap", "\"hexscript\" \"hextransaction\" \"secret\"")
            + HelpExampleRpc("redeemswap", "\"hexscript\", \"hextransaction\", \"secret\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "No wallet loaded");
    }
    CWallet* const pwallet = wallet.get();

    std::vector<unsigned char> contract(ParseHexV(request.params[0], "hexscript"));

    CMutableTransaction contractTx;
    if (!DecodeHexTx(contractTx, request.params[1].get_str())) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Failed to decode contract transaction");
    }

    std::vector<unsigned char> secret(ParseHexV(request.params[2], "secret"));
    if (secret.size() != SECRET_SIZE) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Secret has wrong size");
    }

    EnsureWalletIsUnlocked(*pwallet);

    const CScript contractRedeemScript(contract.begin(), contract.end());
    const CScriptID swapContractAddr(contractRedeemScript);
    const CScript contractPubKeyScript = GetScriptForDestination(ScriptHash(swapContractAddr));

    std::vector<unsigned char> secretHash;
    CKeyID recipient;
    CKeyID refund;
    int64_t locktime;
    int64_t secretSize;
    if (!TryDecodeAtomicSwapScript(contractRedeemScript, secretHash, recipient, refund, locktime, secretSize)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Contract is not an atomic swap script recognized by this tool");
    }

    const int contractOutIndex = FindContractOutput(contractTx, swapContractAddr);
    if (contractOutIndex == -1) {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Transaction does not contain the contract output");
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    auto change = pwallet->GetNewChangeDestination(OutputType::LEGACY);
    if (!change) {
        throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(change).original);
    }
    const CScript outScript = GetScriptForDestination(change.value());

    CMutableTransaction redeemTx;
    redeemTx.nLockTime = (uint32_t)locktime;
    redeemTx.vout.emplace_back(0, outScript);
    redeemTx.vin.emplace_back(COutPoint(contractTx.GetHash(), (uint32_t)contractOutIndex));

    const int redeemTxSize = EstimateRedeemTxSerializeSize(contractRedeemScript, redeemTx.vout);
    const CCoinControl coinControl;
    const CAmount redeemFee = GetMinimumFee(*pwallet, redeemTxSize, coinControl, nullptr);
    redeemTx.vout[0].nValue = contractTx.vout[contractOutIndex].nValue - redeemFee;
    if (IsDust(redeemTx.vout[0], GetDiscardRate(*pwallet))) {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, strprintf("Redeem output value of %d is dust", redeemTx.vout[0].nValue));
    }

    CScript redeemSigScript;
    if (!SignSwapInput(pwallet, contractRedeemScript, contractPubKeyScript, recipient, secret, true,
                       redeemTx, contractTx.vout[contractOutIndex].nValue, redeemSigScript)) {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, "Failed to create redeem script signature");
    }
    redeemTx.vin[0].scriptSig = redeemSigScript;

    UniValue res = SwapTxToUniv(MakeTransactionRef(std::move(redeemTx)));
    res.pushKV("Redeem fee", ValueFromAmount(redeemFee));
    return res;
},
    };
}

RPCHelpMan extractsecret()
{
    return RPCHelpMan{"extractsecret",
        "\nExtract the secret from the initiator's redemption transaction using the known secret hash.\n",
        {
            {"hextransaction", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded redemption transaction"},
            {"secrethash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded hash of redemption secret"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "secret", "The hex-encoded secret for redemption"},
        }},
        RPCExamples{
            HelpExampleCli("extractsecret", "\"hextransaction\" \"secrethash\"")
            + HelpExampleRpc("extractsecret", "\"hextransaction\", \"secrethash\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CMutableTransaction tx;
    if (!DecodeHexTx(tx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Failed to decode redemption transaction");
    }

    std::vector<unsigned char> secretHash(ParseHexV(request.params[1], "secrethash"));
    if (secretHash.size() != CSHA256::OUTPUT_SIZE) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Secret hash has wrong size");
    }

    CSHA256 sha;
    for (const CTxIn& txin : tx.vin) {
        CScript::const_iterator pc = txin.scriptSig.begin();
        std::vector<unsigned char> data, secretHashCalculated(CSHA256::OUTPUT_SIZE, 0);
        while (pc < txin.scriptSig.end())
        {
            opcodetype opcode;
            if (!txin.scriptSig.GetOp(pc, opcode, data)) {
                break;
            }
            if (!data.empty()) {
                sha.Write(data.data(), data.size());
                sha.Finalize(secretHashCalculated.data());
                sha.Reset();
                if (secretHashCalculated == secretHash) {
                    UniValue res(UniValue::VOBJ);
                    res.pushKV("secret", HexStr(data));
                    return res;
                }
            }
        }
    }

    throw JSONRPCError(RPC_TRANSACTION_ERROR, "Transaction does not contain the secret");
},
    };
}

RPCHelpMan refundswap()
{
    return RPCHelpMan{"refundswap",
        "\nCreate a refund of a contract transaction after the fact (e.g. the contract was malleated or the refund fee is now too low).\n",
        {
            {"hexscript", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded contract"},
            {"hextransaction", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded contract transaction"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "txid", "The refund transaction id"},
            {RPCResult::Type::STR_HEX, "hex", "The hex-encoded refund transaction with signature(s)"},
            {RPCResult::Type::STR_AMOUNT, "fee", "The refund transaction fee"},
        }},
        RPCExamples{
            HelpExampleCli("refundswap", "\"hexscript\" \"hextransaction\"")
            + HelpExampleRpc("refundswap", "\"hexscript\", \"hextransaction\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "No wallet loaded");
    }
    CWallet* const pwallet = wallet.get();

    std::vector<unsigned char> scriptData(ParseHexV(request.params[0], "hexscript"));
    const CScript contractRedeemscript(scriptData.begin(), scriptData.end());

    CMutableTransaction tx;
    if (!DecodeHexTx(tx, request.params[1].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Failed to decode contract transaction");
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(*pwallet);

    CMutableTransaction refundTx;
    CAmount refundFee;
    BuildRefundTransaction(pwallet, contractRedeemscript, tx, refundTx, refundFee);

    UniValue res = SwapTxToUniv(MakeTransactionRef(std::move(refundTx)));
    res.pushKV("fee", ValueFromAmount(refundFee));
    return res;
},
    };
}

} // namespace wallet
