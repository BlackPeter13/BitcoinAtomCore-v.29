// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <arith_uint256.h>
#include <hash.h>
#include <tinyformat.h>

uint256 CBlockHeader::GetHash() const
{
    // Atom: block hash commits to the 80-byte legacy header, plus the
    // proof-of-stake flag bit for PoS blocks (matches historical BCA hashes).
    HashWriter writer{};
    writer << nVersion << hashPrevBlock << hashMerkleRoot << nTime << nBits << nNonce;
    if (IsProofOfStake()) {
        uint32_t flags = nFlags & BLOCK_PROOF_OF_STAKE;
        writer << flags;
    }
    return writer.GetHash();
}

unsigned int CBlock::GetStakeEntropyBit(int32_t height) const
{
    (void)height;
    // Last bit of block hash.
    return UintToArith256(GetHash()).GetLow64() & 1llu;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
