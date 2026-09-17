// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <util/time.h>

enum
{
    BLOCK_PROOF_OF_STAKE = (1 << 0), // is proof-of-stake block
    BLOCK_STAKE_ENTROPY  = (1 << 1), // entropy bit for stake modifier
    BLOCK_STAKE_MODIFIER = (1 << 2), // regenerated stake modifier
    BLOCK_NEW_FORMAT = (1 << 31), // postfork block format
};

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    static const int32_t NORMAL_SERIALIZE_SIZE = 84;
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    // Atom: consensus flags (proof-of-stake / stake modifier / new format).
    // Serialized on the wire and disk for post-fork blocks; pre-fork
    // (legacy) contexts must use LegacyBlockHeaderFormatter instead.
    uint32_t nFlags{0};

    CBlockHeader()
    {
        SetNull();
    }

    SERIALIZE_METHODS(CBlockHeader, obj) { READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce, obj.nFlags); }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        nFlags = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    NodeSeconds Time() const
    {
        return NodeSeconds{std::chrono::seconds{nTime}};
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    bool IsProofOfStake() const
    {
        return nFlags & BLOCK_PROOF_OF_STAKE;
    }

    void SetProofOfStake()
    {
        nFlags |= BLOCK_PROOF_OF_STAKE;
    }

    bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }

    bool IsNewFormatBlock() const
    {
        return nFlags & BLOCK_NEW_FORMAT;
    }

    void SetNewFormatBlock()
    {
        nFlags |= BLOCK_NEW_FORMAT;
    }
};

/**
 * Pre-fork (legacy) header serialization: 80-byte header without nFlags.
 * Use explicitly for legacy contexts, e.g.:
 *   s << Using<LegacyBlockHeaderFormatter>(header);
 */
struct LegacyBlockHeaderFormatter {
    FORMATTER_METHODS(CBlockHeader, obj) {
        // 80-byte legacy header (no nFlags). Fresh headers default nFlags
        // to 0 via SetNull(); never mutate here (Serialize takes const).
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce);
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // Atom: block signature for proof-of-stake blocks, signed by the
    // coinbase txout[0]'s owner. Serialized only for PoS blocks.
    std::vector<unsigned char> vchBlockSig;

    // Memory-only flags for caching expensive checks
    mutable bool fChecked;                            // CheckBlock()
    mutable bool m_checked_witness_commitment{false}; // CheckWitnessCommitment()
    mutable bool m_checked_merkle_root{false};        // CheckMerkleRoot()

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj)
    {
        READWRITE(AsBase<CBlockHeader>(obj), obj.vtx);
        // Atom: only proof-of-stake blocks carry a block signature.
        // (Readers start from SetNull(), so no reset is needed here.)
        if (obj.IsProofOfStake()) {
            READWRITE(obj.vchBlockSig);
        }
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
        m_checked_witness_commitment = false;
        m_checked_merkle_root = false;
        vchBlockSig.clear();
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.nFlags         = nFlags;
        return block;
    }

    // Atom: entropy bit for stake modifier (height selects a precomputed
    // table in legacy versions; current implementation derives it from the
    // block hash and ignores height).
    unsigned int GetStakeEntropyBit(int32_t height) const;

    std::string ToString() const;
};

/** Atom: pre-fork (legacy) block serialization: 80-byte header, no flags/sig. */
struct LegacyBlockFormatter {
    FORMATTER_METHODS(CBlock, obj) {
        READWRITE(Using<LegacyBlockHeaderFormatter>(obj));
        READWRITE(TX_WITH_WITNESS(obj.vtx));
    }
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    /** Historically CBlockLocator's version field has been written to network
     * streams as the negotiated protocol version and to disk streams as the
     * client version, but the value has never been used.
     *
     * Hard-code to the highest protocol version ever written to a network stream.
     * SerParams can be used if the field requires any meaning in the future,
     **/
    static constexpr int DUMMY_VERSION = 70016;

    std::vector<uint256> vHave;

    CBlockLocator() = default;

    explicit CBlockLocator(std::vector<uint256>&& have) : vHave(std::move(have)) {}

    SERIALIZE_METHODS(CBlockLocator, obj)
    {
        int nVersion = DUMMY_VERSION;
        READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
