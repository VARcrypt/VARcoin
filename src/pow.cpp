// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cmath>
#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"
#include "bignum.h"

#include "util.h"

unsigned int static KimotoGravityWell(const CBlockIndex* pindexLast, const CBlockHeader *pblock, uint64_t TargetBlocksSpacingSeconds, uint64_t PastBlocksMin, uint64_t PastBlocksMax, uint256 powLimit) {
	/* current difficulty formula, megacoin - kimoto gravity well */
	const CBlockIndex  *BlockLastSolved				= pindexLast;
	const CBlockIndex  *BlockReading				= pindexLast;
	const CBlockHeader *BlockCreating				= pblock;
						BlockCreating				= BlockCreating;
	uint64_t				PastBlocksMass				= 0;
	int64_t				PastRateActualSeconds		= 0;
	int64_t				PastRateTargetSeconds		= 0;
	double				PastRateAdjustmentRatio		= double(1);
	arith_uint256				PastDifficultyAverage;
	arith_uint256				PastDifficultyAveragePrev;
	double				EventHorizonDeviation;
	double				EventHorizonDeviationFast;
	double				EventHorizonDeviationSlow;

	arith_uint256 powLimitArith = UintToArith256(powLimit);

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64_t)BlockLastSolved->nHeight < PastBlocksMin) {
		return powLimitArith.GetCompact();
	}
	
	for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
		if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
		PastBlocksMass++;

		if (i == 1)	{ PastDifficultyAverage.SetCompact(BlockReading->nBits); }
		else        { PastDifficultyAverage = ((arith_uint256().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev; }
		PastDifficultyAveragePrev = PastDifficultyAverage;

		PastRateActualSeconds			= BlockLastSolved->GetBlockTime() - BlockReading->GetBlockTime();
		PastRateTargetSeconds			= TargetBlocksSpacingSeconds * PastBlocksMass;
		PastRateAdjustmentRatio			= double(1);
		if (PastRateActualSeconds < 0) { PastRateActualSeconds = 0; }
		if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
			PastRateAdjustmentRatio			= double(PastRateTargetSeconds) / double(PastRateActualSeconds);
		}
		EventHorizonDeviation			= 1 + (0.7084 * pow((double(PastBlocksMass)/double(144)), -1.228));
		EventHorizonDeviationFast		= EventHorizonDeviation;
		EventHorizonDeviationSlow		= 1 / EventHorizonDeviation;

		if (PastBlocksMass >= PastBlocksMin) {
			if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) { assert(BlockReading); break; }
		}

		if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
		BlockReading = BlockReading->pprev;
	}

	arith_uint256 bnNew(PastDifficultyAverage);

	if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
		bnNew *= PastRateActualSeconds;
		bnNew /= PastRateTargetSeconds;
	}

    if (bnNew > powLimitArith) { bnNew = powLimitArith; }

    return bnNew.GetCoqmpact();
}


unsigned int static KimotoGravityWell_v2(const CBlockIndex* pindexLast, const CBlockHeader *pblock, uint64 TargetBlocksSpacingSeconds, uint64 PastBlocksMin, uint64 PastBlocksMax, uint256 powLimit) {
    /* current difficulty formula, megacoin - kimoto gravity well */
    const CBlockIndex  *BlockLastSolved				= pindexLast;
    const CBlockIndex  *BlockReading				= pindexLast;
    const CBlockHeader *BlockCreating				= pblock;
    BlockCreating				= BlockCreating;
    uint64				PastBlocksMass				= 0;
    int64				PastRateActualSeconds		= 0;
    int64				PastRateTargetSeconds		= 0;
    double				PastRateAdjustmentRatio		= double(1);
    CBigNum				PastDifficultyAverage;
    CBigNum				PastDifficultyAveragePrev;
    double				EventHorizonDeviation;
    double				EventHorizonDeviationFast;
    double				EventHorizonDeviationSlow;

    CBigNum powLimitArith = CBigNum(powLimit);

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64)BlockLastSolved->nHeight < PastBlocksMin) { return powLimitArith.GetCompact(); }

    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
        PastBlocksMass++;

        if (i == 1)	{ PastDifficultyAverage.SetCompact(BlockReading->nBits); }
        else		{
            CBigNum currentBlockDifficulty = CBigNum().SetCompact(BlockReading->nBits);

            PastDifficultyAverage = ((CBigNum().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev;
        }

        PastDifficultyAveragePrev = PastDifficultyAverage;

        PastRateActualSeconds			= BlockLastSolved->GetBlockTime() - BlockReading->GetBlockTime();
        PastRateTargetSeconds			= TargetBlocksSpacingSeconds * PastBlocksMass;
        PastRateAdjustmentRatio			= double(1);
        if (PastRateActualSeconds < 0) { PastRateActualSeconds = 0; }
        if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
            PastRateAdjustmentRatio			= double(PastRateTargetSeconds) / double(PastRateActualSeconds);
        }
        EventHorizonDeviation			= 1 + (0.7084 * pow((double(PastBlocksMass)/double(144)), -1.228));
        EventHorizonDeviationFast		= EventHorizonDeviation;
        EventHorizonDeviationSlow		= 1 / EventHorizonDeviation;

        if (PastBlocksMass >= PastBlocksMin) {
            if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) { assert(BlockReading); break; }
        }
        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
        BlockReading = BlockReading->pprev;
    }

    CBigNum bnNew(PastDifficultyAverage);

    if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
        bnNew *= PastRateActualSeconds;
        bnNew /= PastRateTargetSeconds;
    }
    if (bnNew > powLimitArith) { bnNew = powLimitArith; }

    /// debug print
    LogPrintf("Difficulty Retarget - Kimoto Gravity Well\n");
    LogPrintf("PastRateAdjustmentRatio = %g\n", PastRateAdjustmentRatio);
    LogPrintf("Before: %08x  %s\n", BlockLastSolved->nBits, CBigNum().SetCompact(BlockLastSolved->nBits).getuint256().ToString().c_str());
    LogPrintf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());

    return bnNew.GetCompact();
}



unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    static const int64_t	BlocksTargetSpacing			= 10 * 60; // 10 minutes
    unsigned int		TimeDaySeconds				= 60 * 60 * 24;
    int64_t				PastSecondsMin				= TimeDaySeconds * 0.25;
    int64_t				PastSecondsMax				= TimeDaySeconds * 7;
    uint64_t				PastBlocksMin				= PastSecondsMin / BlocksTargetSpacing;
    uint64_t				PastBlocksMax				= PastSecondsMax / BlocksTargetSpacing;

    LogPrintf("Calculating work required for block: %d\n", pindexLast->nHeight);

    if (pindexLast->nHeight+1 >= 47500)
    {
        return KimotoGravityWell_v2(pindexLast, pblock, BlocksTargetSpacing, PastBlocksMin, PastBlocksMax, params.powLimit);
    }
    else
    {
        return KimotoGravityWell(pindexLast, pblock, BlocksTargetSpacing, PastBlocksMin, PastBlocksMax, params.powLimit);
    }
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
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
