// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018-2020 The DAPS Project developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

std::string CDNSSeedData::getHost(uint64_t requiredServiceBits) const {
    //use default host for non-filter-capable seeds or if we use the default service bits (NODE_NETWORK)
    if (!supportsServiceBitsFiltering || requiredServiceBits == NODE_NETWORK)
        return host;

    return strprintf("x%x.%s", requiredServiceBits, host);
}

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    (0, uint256("0000039a711dba61e12c29fb86542fa059e9616aafe9b4c61e065d393f31535e"))
    (32653, uint256("eaab21ed33e4f1245310693023bbbdb1ae3066b1ba14bebb028a3a994de241c2"))
    (40000, uint256("9ffbac0d42cd54d9ba248c63f36d9a61bc661a04afa78f3ecbcb718bc2f2d21b"))
    (45000, uint256("64c12e8da3b2c07fea03626d05b6d38e736f954a2fc21536a8b8bbdc020d334c"))
    (50000, uint256("abf91e61c4f4c132f70fd35e8806cc0552fc0633c7ff652ba3a4c2d3f76da313"))
    (55000, uint256("ea6b18ed1d3ecb137355c48f932498a7d3700299fdf1482914999659ff76f5fc"))
    (60000, uint256("6736bf033ffd8693a994a4309daa6fcf1949ec682f0079275a18a6b6d5824d29"))
    (65000, uint256("0a1b37f796434886d05b217bfe20f72a9c80d4360a24ac6b964099270047b421"))
    (70000, uint256("ef0c9cb28314963cdea903262ef5d9b7392e4592b49ef52898914761df3deecb"))
    (75000, uint256("dd4977555ce2fa67a24eb4706c916314819fb1aa2d53692f65887c79b1de46dc"))
    (80000, uint256("5f765e960d3ef71146d72adb0df3cd0f28f84267df6572447e3894d5a5c71a22"))
    (85000, uint256("25d5eef4a7c950b3cd211d9153698994e5a7120fe7a196854212763a5725c121"))
    (90000, uint256("708fa5b0c083cb2fb5dec4427932a05cadad248e1ee07e55d260d4db93fd0f0f"))
    (95000, uint256("ee8aef24bf22bd20cc6fa147193455a1792c3bd54bc4bcb974198b0f00fd25e6"))
    (100000, uint256("f5ea8462d802d664ffd17d4311ec08b90b6c7e173fe91fbb1cf875fba8d51b46"))
    (105000, uint256("61a55a787fe2630da750996b8b0e7fd5d3926c4780d60fec61aabe842882c075"))
    (110000, uint256("23c351cfb8d784f209df8ee944cf5819caca6b33b3ee871f952ed047305b5d1f"))
    (115000, uint256("7d2056457c12bba157e63ff9cb22764c279b8862954fc298fcc31a0d33cca6e1"))
    (120000, uint256("676c1258d58f5f5c2c8f4edd62221f34344936691d94bd3ccbd5381505199ffd"))
    (125000, uint256("06c9e0bd74b426f1079aec4ec16d0492ee5787d55c18229ab2bf510d0f29b4cf"))
    (130000, uint256("a6a819a10706c225f6590eb790e7453201fcde628d06817bc71962ed934e6c7f"))
    (135000, uint256("2d3aa77215fa2dba565910a208d4f97e671aea2f9faf769b23e5fb877623357b"))
    (140000, uint256("bfd1387b9672b8f0f8a6605079473a14f0509f4b3556bddaf45244aef47e806b"))
    (145000, uint256("1f8b28270448158f397bae1ca75804212182eea9dab0258a8d0fec6d1d697ce0"))
    (146000, uint256("591dedf96ab6ba5c60389862570a1326e58610af13657e9d5289646704f81e0f"))
    (146100, uint256("fb77b9b4294457cefdcfedf5f39369f7173c8bf2b39bdb241a683fe2e9bac3d3"))
    (146200, uint256("ec4c0b626e5100cc4bdbf3c2b8ae98c7d51a0fd151ff58553d2ca66e0a05515c"))
    (146300, uint256("a85ca48f6e4b1d543e8a838a0b27c49e5f71934b4b28c05d040275c3cec2268d"))
    (146400, uint256("44ec2778fcfc5f737bf1dbd318ecdd31f9e65aad4692f0cea292108861e58234"))
    (146500, uint256("e73bb158b9fc2075bf8c8935548b77f6d2b4bd9bd6e932483c073846bce4a4e0"))
    (146600, uint256("95c6a698083ddc27a8fb342086b055d3823c040f32f5728c9ded7d8fe675bd8b"))
    (146700, uint256("ba7a089a31940f6c8569c07ef25915c50d28182dc78d6af2590a2dc65476c9b2"))
    (146800, uint256("85d7b80f682f4d480e85816786f821576c7f1df182276358ad3917742fa11bd7"))
    (146898, uint256("a0e3853d98c6d60febd57ad2c879e590bda09de271527b396efc5be22ab5ce9e"))
    (146899, uint256("22c90bbb2ae11c3bd5fd6c716d543f8f207e6379e14d26fc04ba7220681dd13b"))
    (146900, uint256("a879e6b5f62ed437d2108366a8152130c21df38322556f06dd71ad08854210b8"))
    (147000, uint256("e60eb87bdbeaee7582826418c8c4504637e51684a3e631b5683390497a4e2535"))
    (147200, uint256("55fcf4abbd7a1b3aa91460378c3b833f9d1569780b0a1e7e6ee2d1b3a4256b24"))
    (147400, uint256("15d8ed0575995a4b3ab8337d87213943abb9e3fba5389c57cbd48a2751f78a5d"))
    (188549, uint256("cfe3696e23e393fa9230f84dfa16a505ac3f40fd147a79adba8a54fa17d24e91"))
    (190000, uint256("733448a9b7429b4387610c0e6d7c62eddf6dea928dc1b53a6d3f64bfa753ff0f"))
    (192500, uint256("d4279eaff8eda44f854d4eebadfd2b321541e998f3e884594f95d32bc301591d"))
    (195000, uint256("d0b7aaa2f79c9dacd1583419fcd36534e42f304dc3ae411eb4cac9937860f2a5"))
    (197500, uint256("d929090435e931bb160fd49905ef0ae6fad00e57e03b036a5b426a18fd712051"))
    (200000, uint256("876a19d823513ad7c58dfd95d5d41e4f7f96450ddb0803001f9581a14f1eebf5"))
    (201000, uint256("bcd41352ffff450691c0c8cfc83ac1d776f679691539baf1c4eadd9b666c820a"))
    (202000, uint256("b1c5ad472a396dca3bd26bd0e607a5e93484315fd85af8ff71610743718a949b"))
    (203000, uint256("ba981cf2bc14d172b7813b9b27022a127dc6d5c59b5febea187c8e751da79eeb"))
    (204000, uint256("f66d3c726fd217908728ccd7405b108d7eb22cfff880bfcbe8995291d9a07fa5"))
    (205000, uint256("31e73a522aca4a4513cd07c4888ffa061d396039ae00812dc673fb181068d880"))
    (206000, uint256("03ef5e49e95d5b6caf6f5c9083a6505aecaaf110d352dfbd3e5ed226673c085f"))
    (207000, uint256("173efe8f8cc450a83353c31c1d06d7b8c284eac46ed2d4c916cac29713a09abe"))
    (208000, uint256("995328748210f12b77700e5589cb5bb4d5b84353682647d1771cbc77e77ffa35"))
    (209577, uint256("5231320be89de8a0fdebbd45d4d0c58abb1ea7a134ba52a11a2036f32d90e66c"))
    (215000, uint256("f114538988fbba92c21418e18dd8f32ed9579f0ee980949467044dfc8b5a444b"))
    (221000, uint256("573a615b64089e31204b9ed642346179858cb4d31749be210f65c95b5e34a5c3"))
    (225000, uint256("87cabfee989514eeebc1b1b15baf91caade99444ae66cda36705161123a04bd0"))
    (230000, uint256("578a5eeee8d8d2d5c9f961db6f4ad42dcc830aaadf103b7bd4dfc6384ddd5d68"))
    (235000, uint256("f91427c4ae7e75c7630c2e3fade78db8ce3aa830b07861435d90a8e2a26222a7"))
    (239830, uint256("a17a68a3399dc67992815f5e0ee3fbac7bb0b3777e64a5446b728dc25bc3b113"))
    (240000, uint256("404633fe3349ee3b8fb6d615ba25646532823f35cd0863f7029d90f9fb00f804"))
    (245000, uint256("0541e509e049e02ce17cff6c1d4178c98a5ac0f3ee2a7db41008db8997389686"))
    (250000, uint256("d4a1b457984d818d728288d2b1fb30355feb3e8e9309b99e165dfc0a22523216"))
    (255000, uint256("a7e29e83aee66c7e2eb097ef8f729dcc44d5235a5533fb357e70fa14cf345bd6"))
    (260000, uint256("556f5deedff1c551551b6fda517fe939e0fb6810d35664fd55b5c5c2b6ec33c7"))
    (265000, uint256("84598b4790a1df395e5ef724c4a2784b27679ef07d9e864ff2fa1b91fcca0751"))
    (270000, uint256("533f7d0f72700d23c3086fbf7f7f01e1b5e0b3c3d24a5f854187eb333610d266"))
    (275000, uint256("7b1d412bc6bf0c994d46c830e6a52fd36e7dbfbde057f44d6c9e8655f50f8720"))
    (280000, uint256("4ddc6eafeb7bcdb14d2836dfe5b5b9d053400a1fb91eae9534e6d7b55e22629a"))
    (285000, uint256("b3b578a10bcc8d9f9251ce6694689c9df8d5956a5b5c536054c75cb39096a1be"))
    (290000, uint256("49c13c93d22f4de36dd8cab41ef8fb879e657198d8b16dd97c4225d199126169"))
    (295000, uint256("e6742077e1d536bdbd4d4e1f440371be5045b604b21bbe5ab9cf5bed30747e46"))
    (300000, uint256("28fe81715aa6450890103e65fbfa3e9d0b4bac3baf86a480ce0c630e82a32e62"))
    (458733, uint256("51d7f917147f3bec3f2e6767fd70c14730a0b0773a7b967e827336e936cf50e2"))
    (458734, uint256("35ff8e3884036187ed56e7d4a4adda3e0f75eac5655afd4cef8605954b28362f"))
    ;
static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1582819136, // * UNIX timestamp of last checkpoint block
    741138,    // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    0        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of(0, uint256("0x00000561b6da32b1b305690648d7eec908a538e9b9f496f1a9ad5d20ed533af8"));
static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1536808115,
    0,
    0};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0x519fc91c13da2eb1301e87ebb7db993f15b57fb1fd7f3e172411bf4262c2efdb"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1536808341,
    0,
    0};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xa4;
        pchMessageStart[1] = 0xb7;
        pchMessageStart[2] = 0x79;
        pchMessageStart[3] = 0x84;
        nDefaultPort = 53572;
        bnProofOfWorkLimit = ~uint256(0) >> 1; // DAPScoin starting difficulty is 1 / 2^12
        nSubsidyHalvingInterval = 210000;
        nMaxReorganizationDepth = 100;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // DAPScoin: 1 day
        nTargetSpacing = 1 * 60;  // DAPScoin: 1 minute
        nMaturity = 100;
        nMasternodeCountDrift = 20;
        MAX_MONEY = 2000000000.0;
        nMaxMoneyOut = MAX_MONEY * COIN;

        /** Height or Time Based Activations **/
        nLastPOWBlock = 500;
        nStartPOABlock = 560;
        nModifierUpdateBlock = 615800;
        nPoABlockTime = 60 * 60; //a PoA block every 30 minutes
        nMinNumPoSBlocks = 59;
        nMaxNumPoSBlocks = 120;

        /**
         * Build the genesis block. Note that the output of the genesis coinbase cannot
         * be spent as it did not originally exist in the database.
         *
         * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
         *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
         *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
         *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
         *   vMerkleTree: e0028e
         */
        const char* pszTimestamp = "30 September 2019 DAPS Coin Development Team - Privacy Is A Right, Not A Privilege";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("041db2a1b75bc00fc1a18e9f8de27c65fede32eb9ac1c11e2587402a66732656d71f7b5de649c8dc7f94aeb433485ce3122ba856644b02e433c2d5fc94ea26bf8e") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1569750052; //09/29/2019 @ 9:40am (UTC)
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 18289272;

        //change blockhash from 0x00000e9468bba3df97334bfb5015543488a0fb38193c82b101472937590e3037 because of transaction structure change
        if(genesis.GetHash()!=uint256("0000039a711dba61e12c29fb86542fa059e9616aafe9b4c61e065d393f31535e"))
        {
            printf("Searchingforgenesisblock...\n");
            uint256 hashTarget=uint256().SetCompact(genesis.nBits);

            printf("hashTarget:%s\n",hashTarget.ToString().c_str());

            while(uint256(genesis.GetHash())>hashTarget)
            {
                printf("loop:%s\n",genesis.GetHash().ToString().c_str());
                ++genesis.nNonce;
                if(genesis.nNonce==0)
                {
                    printf("NONCEWRAPPED,incrementingtime");
                    std::cout<<std::string("NONCEWRAPPED,incrementingtime:\n");
                    ++genesis.nTime;
                }
                if(genesis.nNonce%10000==0)
                {
                    printf("Mainnet:nonce%08u:hash=%s\n",genesis.nNonce,genesis.GetHash().ToString().c_str());
                }
            }
            printf("block.nTime=%u\n",genesis.nTime);
            printf("block.nNonce=%u\n",genesis.nNonce);
            printf("block.GetHash=%s\n",genesis.GetHash().ToString().c_str());
            printf("hashMerkleRoot=%s\n",genesis.hashMerkleRoot.ToString().c_str());

        }



        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0000039a711dba61e12c29fb86542fa059e9616aafe9b4c61e065d393f31535e"));
        assert(genesis.hashMerkleRoot == uint256("4dc798fa29a037570075a87a39c9a54c210f005c4c59c72f32036a87273f4cf8"));

        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("seed.dapscoin.com", "seed.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed1.dapscoin.com", "seed1.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed2.dapscoin.com", "seed2.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed3.dapscoin.com", "seed3.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed4.dapscoin.com", "seed4.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed5.dapscoin.com", "seed5.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed6.dapscoin.com", "seed6.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed7.dapscoin.com", "seed7.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed8.dapscoin.com", "seed8.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed9.dapscoin.com", "seed9.dapscoin.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed.dapscoin-seeds.com", "seed.dapscoin-seeds.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed1.dapscoin-seeds.com", "seed1.dapscoin-seeds.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed2.dapscoin-seeds.com", "seed2.dapscoin-seeds.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed3.dapscoin-seeds.com", "seed3.dapscoin-seeds.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed4.dapscoin-seeds.com", "seed4.dapscoin-seeds.com"));        // Single node address
        vSeeds.push_back(CDNSSeedData("seed5.dapscoin-seeds.com", "seed5.dapscoin-seeds.com"));        // Single node address

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 30);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 13);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 212);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0x2D)(0x25)(0x33).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0x21)(0x31)(0x2B).convert_to_container<std::vector<unsigned char> >();
        // 	BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        nExtCoinType = 0x80000166;

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        nPoolMaxTransactions = 3;
        strObfuscationPoolDummyAddress = "D87q2gC9j6nNrnzCsg4aY6bHMLsT9nUhEw";
        nStartMasternodePayments = 1546809115; //Wed, 25 Jun 2014 20:36:16 GMT
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0xa5;
        pchMessageStart[1] = 0xb8;
        pchMessageStart[2] = 0x7a;
        pchMessageStart[3] = 0x85;
        nDefaultPort = 53574;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // DAPScoin: 1 day
        nTargetSpacing = 1 * 60;  // DAPScoin: 1 minute
        nLastPOWBlock = 500;
        nStartPOABlock = 560;
        nPoABlockTime = 30 * 60;  //1 PoA block every 30 minutes
        nMinNumPoSBlocks = 20;
        nMaturity = 15;
        nMasternodeCountDrift = 4;
        nModifierUpdateBlock = 51197; //approx Mon, 17 Apr 2017 04:00:00 GMT
        MAX_MONEY = 5000000000.0;
        nMaxMoneyOut = MAX_MONEY * COIN;
        nBlockEnforceSerialRange = 1; //Enforce serial range starting this block
        nBlockRecalculateAccumulators = 9908000; //Trigger a recalculation of accumulators
        nBlockFirstFraudulent = 9891737; //First block that bad serials emerged
        nBlockLastGoodCheckpoint = 9891730; //Last valid accumulator checkpoint
        nBlockEnforceInvalidUTXO = 9902850; //Start enforcing the invalid UTXO's

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1590109816;
        genesis.nNonce = 16517940;

        if(genesis.GetHash()!=uint256("00000bbcb4a383121aba2a64bc37241b91ea0be6c7584e869d3ca1c05b03a793"))
        {
            printf("Searchingforgenesisblock...\n");
            uint256 hashTarget=uint256().SetCompact(genesis.nBits);

            printf("hashTarget:%s\n",hashTarget.ToString().c_str());

            while(uint256(genesis.GetHash())>hashTarget)
            {
                printf("loop:%s\n",genesis.GetHash().ToString().c_str());
                ++genesis.nNonce;
                if(genesis.nNonce==0)
                {
                    printf("NONCEWRAPPED,incrementingtime");
                    std::cout<<std::string("NONCEWRAPPED,incrementingtime:\n");
                    ++genesis.nTime;
                }
                if(genesis.nNonce%10000==0)
                {
                    printf("Mainnet:nonce%08u:hash=%s\n",genesis.nNonce,genesis.GetHash().ToString().c_str());
                }
            }
            printf("block.nTime=%u\n",genesis.nTime);
            printf("block.nNonce=%u\n",genesis.nNonce);
            printf("block.GetHash=%s\n",genesis.GetHash().ToString().c_str());
            printf("hashMerkleRoot=%s\n",genesis.hashMerkleRoot.ToString().c_str());

        }

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("00000bbcb4a383121aba2a64bc37241b91ea0be6c7584e869d3ca1c05b03a793"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("testnet.dapscoin-seeds.com", "testnet.dapscoin-seeds.com"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet dapscoin addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet dapscoin script addresses start with '8' or '9'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        // Testnet dapscoin BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        // Testnet dapscoin BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        // Testnet dapscoin BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 0x80000001;

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;
        strObfuscationPoolDummyAddress = "y57cqfGRkekRyDRNeJiLtYVEbvhXrNbmox";
        nStartMasternodePayments = 1420837558; //Fri, 09 Jan 2015 21:05:58 GMT
        nBudget_Fee_Confirmations = 3; // Number of confirmations for the finalization fee. We have to make this very short
                                       // here because we only have a 8 block finalization window on testnet
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xa1;
        pchMessageStart[1] = 0xcf;
        pchMessageStart[2] = 0x7e;
        pchMessageStart[3] = 0xac;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 24 * 60 * 60; // Dapscoin: 1 day
        nTargetSpacing = 1 * 60;        // Dapscoin: 1 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime = 1569319143;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 12359;

        if(genesis.GetHash()!=uint256("2ed32054ce47f012ff186e6116b4906a8cd9d73ff5c689a8623bf36aed774536"))
        {
            printf("Searchingforgenesisblock...\n");
            uint256 hashTarget=uint256().SetCompact(genesis.nBits);

            printf("hashTarget:%s\n",hashTarget.ToString().c_str());

            while(uint256(genesis.GetHash())>hashTarget)
            {
                printf("loop:%s\n",genesis.GetHash().ToString().c_str());
                ++genesis.nNonce;
                if(genesis.nNonce==0)
                {
                    printf("NONCEWRAPPED,incrementingtime");
                    std::cout<<std::string("NONCEWRAPPED,incrementingtime:\n");
                    ++genesis.nTime;
                }
                if(genesis.nNonce%10000==0)
                {
                    printf("Mainnet:nonce%08u:hash=%s\n",genesis.nNonce,genesis.GetHash().ToString().c_str());
                }
            }
            printf("block.nTime=%u\n",genesis.nTime);
            printf("block.nNonce=%u\n",genesis.nNonce);
            printf("block.GetHash=%s\n",genesis.GetHash().ToString().c_str());
            printf("hashMerkleRoot=%s\n",genesis.hashMerkleRoot.ToString().c_str());

        }

        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 51476;

        assert(hashGenesisBlock == uint256("2ed32054ce47f012ff186e6116b4906a8cd9d73ff5c689a8623bf36aed774536"));

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

static CChainParams* pCurrentParams = 0;

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
