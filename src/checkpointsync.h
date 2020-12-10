// Copyright (c) 2011-2013 PPCoin developers
// Copyright (c) 2013 Primecoin developers
// Distributed under conditional MIT/X11 open source software license
// see the accompanying file COPYING
#ifndef BITCOIN_CHECKPOINTSYNC_H
#define  BITCOIN_CHECKPOINTSYNC_H

#include <net.h>
#include <hash.h>
#include <netmessagemaker.h>
#include <util/system.h>
#include <arith_uint256.h>

class uint256;
class CBlock;
class CBlockIndex;
class CSyncCheckpoint;
class CValidationState;
class CCoinsViewCache;

extern uint256 hashSyncCheckpoint;
extern CSyncCheckpoint checkpointMessage;
extern uint256 hashInvalidCheckpoint;
extern RecursiveMutex cs_hashSyncCheckpoint;
extern std::string strCheckpointWarning;

bool WriteSyncCheckpoint(const uint256& hashCheckpoint);
bool AcceptPendingSyncCheckpoint();
uint256 AutoSelectSyncCheckpoint();
bool CheckSyncCheckpoint(const CBlockIndex* pindexNew);
bool ResetSyncCheckpoint();
bool CheckCheckpointPubKey();
bool SetCheckpointPrivKey(std::string strPrivKey);
bool SendSyncCheckpoint(uint256 hashCheckpoint);
bool SetBestChain(CValidationState& state, CBlockIndex* pindexNew);

// Synchronized checkpoint (introduced first in ppcoin)
class CUnsignedSyncCheckpoint
{
public:
    int nVersion;
    uint256 hashCheckpoint;      // checkpoint block

    SERIALIZE_METHODS(CUnsignedSyncCheckpoint, obj)
    {
        READWRITE(obj.nVersion, obj.hashCheckpoint);
    }

    void SetNull()
    {
        nVersion = 1;
        hashCheckpoint = ArithToUint256(arith_uint256(0));
    }    

    std::string ToString() const
    {
        return strprintf(
                "CSyncCheckpoint(\n"
                "    nVersion       = %d\n"
                "    hashCheckpoint = %s\n"
                ")\n",
            nVersion,
            hashCheckpoint.ToString().c_str());
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }
};

class CSyncCheckpoint : public CUnsignedSyncCheckpoint
{
public:
    static std::string strMasterPrivKey;
    std::vector<unsigned char> vchMsg;
    std::vector<unsigned char> vchSig;

    CSyncCheckpoint()
    {
        SetNull();
    }

    SERIALIZE_METHODS(CSyncCheckpoint, obj)
    {
        READWRITE(obj.vchMsg, obj.vchSig);
    }

    void SetNull()
    {
        CUnsignedSyncCheckpoint::SetNull();
        vchMsg.clear();
        vchSig.clear();
    }

    bool IsNull() const
    {
        return (hashCheckpoint == uint256());
    }

    uint256 GetHash() const
    {
        return Hash(vchMsg);
    }

    bool RelayTo(CNode* pfrom) const
    {
        // returns true if wasn't already sent
        if (g_connman && pfrom->hashCheckpointKnown != hashCheckpoint)
        {
            pfrom->hashCheckpointKnown = hashCheckpoint;
            g_connman->PushMessage(pfrom, CNetMsgMaker(pfrom->GetCommonVersion()).Make(NetMsgType::CHECKPOINT, *this));
            return true;
        }
        return false;
    }

    bool CheckSignature();
    bool ProcessSyncCheckpoint();
};

#endif
