// Copyright (c) 2012-2013 The PPCoin developers
// Distributed under the GPL3 software license, see the accompanying
// file COPYING or http://www.gnu.org/licenses/gpl.html.
#ifndef BITCOIN_ATOM_KERNEL_H
#define BITCOIN_ATOM_KERNEL_H

#include <chain.h>

#include <consensus/validation.h>
#include <primitives/block.h>
#include <primitives/transaction.h>

class CBlock;
class COutPoint;
class CTransaction;
class CTxOut;
class ChainstateManager;
class CTxMemPool;
namespace Consensus { struct Params; }

// MODIFIER_INTERVAL_RATIO:
// ratio of group interval length between the last group and the first group
static const int MODIFIER_INTERVAL_RATIO = 3;

// Compute the hash modifier for proof-of-stake.
// Requires cs_main (walks the block index and resolves candidates).
bool ComputeNextStakeModifier(ChainstateManager& chainman, const CBlockIndex* pindexCurrent, const Consensus::Params& consensus, uint64_t& nStakeModifier, bool& fGeneratedStakeModifier);

// Check whether stake kernel meets hash target.
// Sets hashProofOfStake on success return.
bool CheckStakeKernelHash(const Consensus::Params& consensus, const CBlockIndex* pindexTip, unsigned int nBits, const CBlockHeader& blockFrom, unsigned int nTxPrevOffset, const CTxOut& txOutPrev, const COutPoint& prevout, unsigned int nTimeTx, uint256& hashProofOfStake, bool fPrintProofOfStake=false);

// Check kernel hash target and coinstake signature.
// Sets hashProofOfStake on success return.
// Requires cs_main.
bool CheckProofOfStake(BlockValidationState& state, ChainstateManager& chainman, const CTxMemPool* mempool, const CTransactionRef& tx, unsigned int nBits, uint256& hashProofOfStake, unsigned int nBlockTime);

// Get stake modifier checksum
unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex);

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, unsigned int nStakeModifierChecksum);

#endif // BITCOIN_ATOM_KERNEL_H
