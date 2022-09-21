// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <warnings.h>

#include <sync.h>
#include <util/string.h>
#include <checkpointsync.h>
#include <util/system.h>
#include <util/translation.h>

#include <vector>

static Mutex g_warnings_mutex;
static bilingual_str g_misc_warnings GUARDED_BY(g_warnings_mutex);
static bool fLargeWorkInvalidChainFound GUARDED_BY(g_warnings_mutex) = false;

void SetMiscWarning(const bilingual_str& warning)
{
    LOCK(g_warnings_mutex);
    g_misc_warnings = warning;
}

void SetfLargeWorkInvalidChainFound(bool flag)
{
    LOCK(g_warnings_mutex);
    fLargeWorkInvalidChainFound = flag;
}

bilingual_str GetWarnings(bool verbose)
{
    bilingual_str warnings_concise;
    std::vector<bilingual_str> warnings_verbose;

    LOCK(g_warnings_mutex);

    // Pre-release build warning
    if (!CLIENT_VERSION_IS_RELEASE) {
        warnings_concise = _("This is a pre-release test build - use at your own risk - do not use for mining or merchant applications");
        warnings_verbose.emplace_back(warnings_concise);
    }

    // Checkpoint warning
    if (strCheckpointWarning != "")
    {
        warnings_concise = strCheckpointWarning;
        warnings_verbose += (warnings_verbose.empty() ? "" : warning_separator) + strCheckpointWarning;
    }

    // Misc warnings like out of disk space and clock is wrong
    if (!g_misc_warnings.empty()) {
        warnings_concise = g_misc_warnings;
        warnings_verbose.emplace_back(warnings_concise);
    }

    if (fLargeWorkInvalidChainFound) {
        warnings_concise = _("Warning: We do not appear to fully agree with our peers! You may need to upgrade, or other nodes may need to upgrade.");
        warnings_verbose.emplace_back(warnings_concise);
    }

    // If detected invalid checkpoint enter safe mode
    if (hashInvalidCheckpoint != ArithToUint256(arith_uint256(0)))
    {
        warnings_concise = "Warning: Inconsistent checkpoint found! Stop enforcing checkpoints and notify developers to resolve the issue.";
        warnings_verbose += (warnings_verbose.empty() ? "" : warning_separator) + _("Warning: Inconsistent checkpoint found! Stop enforcing checkpoints and notify developers to resolve the issue.").translated;
    }

    if (verbose) {
        return Join(warnings_verbose, Untranslated("<hr />"));
    }

    return warnings_concise;
}
