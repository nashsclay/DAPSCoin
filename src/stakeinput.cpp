// Copyright (c) 2017 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "main.h"
#include "stakeinput.h"
#include "wallet/wallet.h"

//!PRCY Stake
bool CPrcyStake::SetInput(CTransaction txPrev, unsigned int n)
{
    this->txFrom = txPrev;
    this->nPosition = n;
    return true;
}

bool CPrcyStake::GetTxFrom(CTransaction& tx)
{
    tx = txFrom;
    return true;
}

bool CPrcyStake::CreateTxIn(CWallet* pwallet, CTxIn& txIn, uint256 hashTxOut)
{
    CPubKey sharedSec;
    txIn = CTxIn(txFrom.GetHash(), nPosition);

    const CWalletTx* pWalletTx = pwalletMain->GetWalletTx(txFrom.GetHash());
    pwalletMain->computeSharedSec(txFrom, pWalletTx->vout[nPosition], sharedSec);

    //copy encryption key so that full nodes can decode the amount in the txin
    std::copy(sharedSec.begin(), sharedSec.begin() + 33, std::back_inserter(txIn.encryptionKey));

    CScript scriptPubKeyKernel = txFrom.vout[nPosition].scriptPubKey;

    if (!pwalletMain->generateKeyImage(scriptPubKeyKernel, txIn.keyImage)) {
        LogPrintf("CreateCoinStake : cannot generate key image\n");
        return false;
    }
    return true;
}

CAmount CPrcyStake::GetValue()
{
    if (txFrom.IsCoinBase() || txFrom.IsCoinStake()) {
        return txFrom.vout[nPosition].nValue;
    }

    const CWalletTx* pWalletTx = pwalletMain->GetWalletTx(txFrom.GetHash());
    if (!pWalletTx) {
        return 0;
    }

    return pwalletMain->getCTxOutValue(*pWalletTx, pWalletTx->vout[nPosition]);
}

bool CPrcyStake::CreateTxOuts(CWallet* pwallet, std::vector<CTxOut>& vout)
{
    std::vector<valtype> vSolutions;
    txnouttype whichType;
    CScript scriptPubKeyKernel = txFrom.vout[nPosition].scriptPubKey;

    CKey view, spend;
    pwalletMain->myViewPrivateKey(view);
    pwalletMain->mySpendPrivateKey(spend);
    CPubKey viewPub = view.GetPubKey();
    CPubKey spendPub = spend.GetPubKey();

    if (!Solver(scriptPubKeyKernel, whichType, vSolutions)) {
        LogPrintf("CreateCoinStake : failed to parse kernel\n");
        return false;
    }

    if (whichType != TX_PUBKEY && whichType != TX_PUBKEYHASH)
        return false; // only support pay to public key and pay to address

    CScript scriptPubKey;
    if (whichType == TX_PUBKEYHASH) // pay to address type
    {
        //convert to pay to public key type
        CKey key;
        if (!pwallet->GetKey(uint160(vSolutions[0]), key))
            return false;

        scriptPubKey << key.GetPubKey() << OP_CHECKSIG;
    } else
        scriptPubKey = scriptPubKeyKernel;

    //first UTXO for the staked amount
    //create a new pubkey
    CKey myTxPriv;
    myTxPriv.MakeNewKey(true);
    CPubKey txPub = myTxPriv.GetPubKey();
    CPubKey newPub;
    CWallet::ComputeStealthDestination(myTxPriv, viewPub, spendPub, newPub);
    scriptPubKey = GetScriptForDestination(newPub);
    CTxOut out(0, scriptPubKey);
    std::copy(txPub.begin(), txPub.end(), std::back_inserter(out.txPub));
    vout.emplace_back(out);

    //second UTXO for staking reward
    //create a new pubkey
    CKey myTxPrivStaking;
    myTxPrivStaking.MakeNewKey(true);
    CPubKey txPubStaking = myTxPrivStaking.GetPubKey();
    CPubKey newPubStaking;
    CWallet::ComputeStealthDestination(myTxPrivStaking, viewPub, spendPub, newPubStaking);
    CScript scriptPubKeyOutStaking = GetScriptForDestination(newPubStaking);
    CTxOut outStaking(0, scriptPubKeyOutStaking);
    std::copy(txPubStaking.begin(), txPubStaking.end(), std::back_inserter(outStaking.txPub));
    vout.emplace_back(outStaking);

    return true;
}

bool CPrcyStake::GetModifier(uint64_t& nStakeModifier)
{
    int nStakeModifierHeight = 0;
    int64_t nStakeModifierTime = 0;
    GetIndexFrom();
    if (!pindexFrom)
        return error("%s: failed to get index from", __func__);

    if (!GetKernelStakeModifier(pindexFrom->GetBlockHash(), nStakeModifier, nStakeModifierHeight, nStakeModifierTime, false))
        return error("CheckStakeKernelHash(): failed to get kernel stake modifier \n");

    return true;
}

CDataStream CPrcyStake::GetUniqueness()
{
    //The unique identifier for a PRCY stake is the outpoint
    CDataStream ss(SER_NETWORK, 0);
    ss << nPosition << txFrom.GetHash();
    return ss;
}

//The block that the UTXO was added to the chain
CBlockIndex* CPrcyStake::GetIndexFrom()
{
    uint256 hashBlock = 0;
    CTransaction tx;
    if (GetTransaction(txFrom.GetHash(), tx, hashBlock, true)) {
        // If the index is in the chain, then set it as the "index from"
        if (mapBlockIndex.count(hashBlock)) {
            CBlockIndex* pindex = mapBlockIndex.at(hashBlock);
            if (chainActive.Contains(pindex))
                pindexFrom = pindex;
        }
    } else {
        LogPrintf("%s : failed to find tx %s\n", __func__, txFrom.GetHash().GetHex());
    }

    return pindexFrom;
}
