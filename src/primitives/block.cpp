// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2020 The DAPS Project developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "script/standard.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "util.h"

uint256 PoSBlockSummary::GetHash() const {
    return Hash(BEGIN(hash), END(hash),
                BEGIN(nTime), END(nTime),
                BEGIN(height), END(height));
}
/*
int scanhash_scrypt(uint32_t *pdata) {
    uint32_t data[20], hash[8];
    unsigned char scratchbuf = malloc((size_t)N * 128 + 63);
    uint32_t midstate[8];
    uint32_t n = pdata[19] - 1;
    const uint32_t Htarg = ptarget[7];
    int throughput = scrypt_best_throughput();
    int i;

#ifdef HAVE_SHA256_4WAY
    if (sha256_use_4way())
        throughput *= 4;
#endif

    for (i = 0; i < throughput; i++)
        memcpy(data + i * 20, pdata, 80);

    sha256_init(midstate);
    sha256_transform(midstate, data, 0);

#if defined(HAVE_SHA256_4WAY)
        if (throughput == 4)
            scrypt_1024_1_1_256_4way(data, hash, midstate, scratchbuf, N);
        else
#endif
#if defined(HAVE_SCRYPT_3WAY) && defined(HAVE_SHA256_4WAY)
        if (throughput == 12)
            scrypt_1024_1_1_256_12way(data, hash, midstate, scratchbuf, N);
        else
#endif
#if defined(HAVE_SCRYPT_6WAY)
        if (throughput == 24)
            scrypt_1024_1_1_256_24way(data, hash, midstate, scratchbuf, N);
        else
#endif
#if defined(HAVE_SCRYPT_3WAY)
        if (throughput == 3)
            scrypt_1024_1_1_256_3way(data, hash, midstate, scratchbuf, N);
        else
#endif
        scrypt_1024_1_1_256(data, hash, midstate, scratchbuf, N);
    }
}*/

uint256 CBlockHeader::ComputeMinedHash() const
{
    if (IsPoABlockByVersion()) {
        return Hash(BEGIN(nVersion), END(nVersion),
            BEGIN(hashMerkleRoot), END(hashMerkleRoot),
            BEGIN(hashPrevPoABlock), END(hashPrevPoABlock),
            BEGIN(hashPoAMerkleRoot), END(hashPoAMerkleRoot),
            BEGIN(nTime), END(nTime),
            BEGIN(nBits), END(nBits),
            BEGIN(nNonce), END(nNonce));
    }
    return UINT256_ZERO;
}

uint256 CBlockHeader::GetHash() const
{
    if (IsPoABlockByVersion()) {
#if defined(WORDS_BIGENDIAN)
        // TODO: Big Endian PoA hashing
#else // Can take shortcut for little endian
        return Hash(BEGIN(hashPrevBlock), END(hashPrevBlock),
            BEGIN(minedHash), END(minedHash));
#endif
    }
    if (nVersion >= 5)  {
#if defined(WORDS_BIGENDIAN)
        uint8_t data[80];
        WriteLE32(&data[0], nVersion);
        memcpy(&data[4], hashPrevBlock.begin(), hashPrevBlock.size());
        memcpy(&data[36], hashMerkleRoot.begin(), hashMerkleRoot.size());
        WriteLE32(&data[68], nTime);
        WriteLE32(&data[72], nBits);
        WriteLE32(&data[76], nAccumulatorCheckpoint);
        return Hash(data, data + 80);
#else // Can take shortcut for little endian
        return Hash(BEGIN(nVersion), END(nAccumulatorCheckpoint));
#endif
    }
    if (nVersion < 4)  {
#if defined(WORDS_BIGENDIAN)
        uint8_t data[80];
        WriteLE32(&data[0], nVersion);
        memcpy(&data[4], hashPrevBlock.begin(), hashPrevBlock.size());
        memcpy(&data[36], hashMerkleRoot.begin(), hashMerkleRoot.size());
        WriteLE32(&data[68], nTime);
        WriteLE32(&data[72], nBits);
        WriteLE32(&data[76], nNonce);
        return HashQuark(data, data + 80);
#else // Can take shortcut for little endian
        return HashQuark(BEGIN(nVersion), END(nNonce));
#endif
    }
    // version >= 6
    return SerializeHash(*this);
}

uint256 CBlock::ComputePoAMerkleTree(bool* fMutated) const
{
    std::vector<uint256> poaMerkleTree;
    poaMerkleTree.reserve(posBlocksAudited.size() * 2 + 16); // Safe upper bound for the number of total nodes.
    for (std::vector<PoSBlockSummary>::const_iterator it(posBlocksAudited.begin()); it != posBlocksAudited.end(); ++it)
        poaMerkleTree.push_back(it->GetHash());
    int j = 0;
    bool mutated = false;
    for (int nSize = posBlocksAudited.size(); nSize > 1; nSize = (nSize + 1) / 2)
    {
        for (int i = 0; i < nSize; i += 2)
        {
            int i2 = std::min(i+1, nSize-1);
            if (i2 == i + 1 && i2 + 1 == nSize && poaMerkleTree[j+i] == poaMerkleTree[j+i2]) {
                // Two identical hashes at the end of the list at a particular level.
                mutated = true;
            }
            poaMerkleTree.push_back(Hash(BEGIN(poaMerkleTree[j+i]),  END(poaMerkleTree[j+i]),
                                       BEGIN(poaMerkleTree[j+i2]), END(poaMerkleTree[j+i2])));
        }
        j += nSize;
    }
    if (fMutated) {
        *fMutated = mutated;
    }
    return (poaMerkleTree.empty() ? UINT256_ZERO : poaMerkleTree.back());
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    if (IsProofOfAudit()) {
        s << strprintf("PoABlock(hash=%s, ver=%d, hashPrevBlock=%s, hashPrevPoABlock=%s, hashMerkleRoot=%s, hashPoAMerkleRoot=%s, minedHash=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u, PoSBlocks=%u)\n",
            GetHash().ToString(),
            nVersion,
            hashPrevBlock.ToString(),
            hashPrevPoABlock.ToString(),
            hashMerkleRoot.ToString(),
            hashPoAMerkleRoot.ToString(),
            minedHash.ToString(),
            nTime, nBits, nNonce,
            vtx.size(),
            posBlocksAudited.size());
    } else {
        s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
            GetHash().ToString(),
            nVersion,
            hashPrevBlock.ToString(),
            hashMerkleRoot.ToString(),
            nTime, nBits, nNonce,
            vtx.size());
    }
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i].ToString() << "\n";
    }
    return s.str();
}

void CBlock::print() const
{
    LogPrintf("%s", ToString());
}
