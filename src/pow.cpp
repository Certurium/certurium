// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

static const int64_t DIFFICULTY_ADJUST_WINDOW = 60;

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    if (params.fPowAllowMinDifficultyBlocks)
        return UintToArith256(params.powLimit).GetCompact();

    assert(pindexLast != nullptr);
    const auto BitsToArith256 = [](uint32_t bits){
        arith_uint256 value;
        value.SetCompact(bits);
        return value;
    };

    const size_t needed_block_count = DIFFICULTY_ADJUST_WINDOW;
    std::vector<std::pair<int64_t, arith_uint256>> past_data;
    past_data.reserve(needed_block_count);
    for (auto p = pindexLast; p; p = p->pprev) {
        past_data.emplace_back(p->GetBlockTime(), BitsToArith256(p->nBits));
        if (past_data.size() == needed_block_count)
            return CalculateNextWorkRequired(past_data, params);
    }

    const auto last_ts_delta = past_data.size() > 2 ?
        past_data.front().first - past_data.at(1).first :
        params.nPowTargetSpacing;
    auto last_ts = past_data.size() > 1 ?
        std::next(past_data.crbegin())->first - last_ts_delta :
        past_data.front().first;
    const auto last_diff = past_data.front().second;
    // fill in simulated blocks with values from the previous real block
    for (size_t i = past_data.size(); i < needed_block_count; i++) {
        last_ts = last_ts - last_ts_delta;
        past_data.emplace_back(last_ts, last_diff);
    }
    assert(past_data.size() == needed_block_count);
    return CalculateNextWorkRequired(past_data, params);
}

unsigned int CalculateNextWorkRequired(const std::vector<std::pair<int64_t, arith_uint256>>& past_data, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return past_data.front().second.GetCompact();


    const int64_t DAMP_FACTOR = 3;
    const auto BLOCK_TIME_WINDOW = (DIFFICULTY_ADJUST_WINDOW - 1) * params.nPowTargetSpacing;
    const auto UPPER_TIME_BOUND = BLOCK_TIME_WINDOW * 2;
    const auto LOWER_TIME_BOUND = BLOCK_TIME_WINDOW / 2;

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 targetAvg;
    for (const auto& data: past_data)
        targetAvg += data.second;
    targetAvg /= DIFFICULTY_ADJUST_WINDOW;
    const auto ts_delta = past_data.front().first - past_data.back().first;
    const auto ts_damp = DAMP_FACTOR * targetAvg > bnPowLimit ?
        ts_delta :
        (ts_delta + (DAMP_FACTOR - 1) * BLOCK_TIME_WINDOW) / DAMP_FACTOR;

    const auto adj_ts = std::max(std::min(ts_damp, UPPER_TIME_BOUND), LOWER_TIME_BOUND);
    const arith_uint256 target = targetAvg * adj_ts / BLOCK_TIME_WINDOW;
    return target > bnPowLimit ? bnPowLimit.GetCompact() : target.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
