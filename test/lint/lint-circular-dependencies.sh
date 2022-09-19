#!/usr/bin/env bash
#
# Copyright (c) 2018-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check for circular dependencies

export LC_ALL=C

EXPECTED_CIRCULAR_DEPENDENCIES=(
    "activemasternode -> masternode-sync -> activemasternode"
    "activemasternode -> masternodeman -> activemasternode"
    #"budget/budgetmanager -> masternode-sync -> budget/budgetmanager"
    #"budget/budgetmanager -> net_processing -> budget/budgetmanager"
    #"budget/budgetmanager -> validation -> budget/budgetmanager"
    #"budget/budgetmanager -> wallet/wallet -> budget/budgetmanager"
    #"chain -> legacy/stakemodifier -> chain"
    "chainparams -> checkpoints -> chainparams"
    "chainparamsbase -> util/system -> chainparamsbase"
    #"checkpoints -> validation -> checkpoints"
    #"consensus/params -> consensus/upgrades -> consensus/params"
    "crypter -> wallet/wallet -> crypter"
    #"evo/deterministicmns -> evo/providertx -> evo/deterministicmns"
    #"evo/deterministicmns -> evo/specialtx -> evo/deterministicmns"
    #"evo/deterministicmns -> masternodeman -> evo/deterministicmns"
    #"evo/deterministicmns -> validationinterface -> evo/deterministicmns"
    #"evo/providertx -> evo/specialtx -> evo/providertx"
    "init -> masternodeman -> init"
    "init -> rpc/server -> init"
    #"init -> validation -> init"
    #"kernel -> validation -> kernel"
    "masternode -> masternode-sync -> masternode"
    "masternode -> masternodeman -> masternode"
    "masternode -> wallet/wallet -> masternode"
    "masternode-payments -> masternode-sync -> masternode-payments"
    "masternode-payments -> masternodeman -> masternode-payments"
    "masternode-payments -> net_processing -> masternode-payments"
    #"masternode-payments -> validation -> masternode-payments"
    "masternode-sync -> masternodeman -> masternode-sync"
    #"masternode-sync -> validation -> masternode-sync"
    "masternodeman -> net_processing -> masternodeman"
    #"masternodeman -> validation -> masternodeman"
    "net -> netmessagemaker -> net"
    #"policy/fees -> txmempool -> policy/fees"
    #"policy/policy -> validation -> policy/policy"
    #"txmempool -> validation -> txmempool"
    #"validation -> validationinterface -> validation"
    #"wallet/fees -> wallet/wallet -> wallet/fees"
    #"wallet/scriptpubkeyman -> wallet/wallet -> wallet/scriptpubkeyman"
    "wallet/wallet -> wallet/walletdb -> wallet/wallet"
    "chain -> chainparams -> checkpoints -> chain"
    #"chain -> legacy/stakemodifier -> stakeinput -> chain"
    #"chain -> legacy/stakemodifier -> validation -> chain"
    #"chainparams -> checkpoints -> validation -> chainparams"
    #"chainparamsbase -> util/system -> logging -> chainparamsbase"
    #"coins -> policy/fees -> txmempool -> coins"
    #"evo/deterministicmns -> masternode -> init -> evo/deterministicmns"
    #"evo/deterministicmns -> masternode -> masternode-sync -> evo/deterministicmns"
    #"evo/deterministicmns -> masternodeman -> net_processing -> evo/deterministicmns"
    #"evo/deterministicmns -> masternode -> wallet/wallet -> evo/deterministicmns"
    #"evo/deterministicmns -> validation -> validationinterface -> evo/deterministicmns"
    "kernel -> stakeinput -> wallet/wallet -> kernel"
    #"masternode-sync -> masternodeman -> net_processing -> masternode-sync"
    "primitives/transaction -> script/standard -> script/interpreter -> primitives/transaction"
    #"chain -> legacy/stakemodifier -> validation -> evo/specialtx -> chain"
    #"chain -> legacy/stakemodifier -> validation -> validationinterface -> chain"
    #"chain -> legacy/stakemodifier -> stakeinput -> txdb -> chain"
    #"chain -> legacy/stakemodifier -> validation -> undo -> chain"
    #"chain -> legacy/stakemodifier -> validation -> poa -> chain"
    #"chainparams -> checkpoints -> validation -> consensus/tx_verify -> chainparams"
    #"chainparams -> checkpoints -> validation -> evo/specialtx -> chainparams"
    #"chainparams -> checkpoints -> validation -> poa -> chainparams"
    #"coins -> policy/fees -> policy/policy -> validation -> coins"
    #"addrman -> timedata -> chainparams -> checkpoints -> validation -> addrman"
    #"blocksignature -> primitives/block -> script/sign -> policy/policy -> validation -> blocksignature"
    #"coins -> policy/fees -> policy/policy -> validation -> txdb -> coins"
    #"consensus/tx_verify -> evo/specialtx -> primitives/block -> script/sign -> policy/policy -> consensus/tx_verify"
    #"consensus/merkle -> primitives/block -> script/sign -> policy/policy -> validation -> consensus/merkle"
    #"evo/specialtx -> primitives/block -> script/sign -> policy/policy -> validation -> evo/specialtx"
    #"policy/policy -> validation -> poa -> primitives/block -> script/sign -> policy/policy"
    #"chain -> legacy/stakemodifier -> stakeinput -> wallet/wallet -> spork -> net_processing -> chain"
)

EXIT_CODE=0

CIRCULAR_DEPENDENCIES=()

IFS=$'\n'
for CIRC in $(cd src && ../contrib/devtools/circular-dependencies.py {*,*/*,*/*/*}.{h,cpp} | sed -e 's/^Circular dependency: //'); do
    CIRCULAR_DEPENDENCIES+=( "$CIRC" )
    IS_EXPECTED_CIRC=0
    for EXPECTED_CIRC in "${EXPECTED_CIRCULAR_DEPENDENCIES[@]}"; do
        if [[ "${CIRC}" == "${EXPECTED_CIRC}" ]]; then
            IS_EXPECTED_CIRC=1
            break
        fi
    done
    if [[ ${IS_EXPECTED_CIRC} == 0 ]]; then
        echo "A new circular dependency in the form of \"${CIRC}\" appears to have been introduced."
        echo
        EXIT_CODE=1
    fi
done

for EXPECTED_CIRC in "${EXPECTED_CIRCULAR_DEPENDENCIES[@]}"; do
    IS_PRESENT_EXPECTED_CIRC=0
    for CIRC in "${CIRCULAR_DEPENDENCIES[@]}"; do
        if [[ "${CIRC}" == "${EXPECTED_CIRC}" ]]; then
            IS_PRESENT_EXPECTED_CIRC=1
            break
        fi
    done
    if [[ ${IS_PRESENT_EXPECTED_CIRC} == 0 ]]; then
        echo "Good job! The circular dependency \"${EXPECTED_CIRC}\" is no longer present."
        echo "Please remove it from EXPECTED_CIRCULAR_DEPENDENCIES in $0"
        echo "to make sure this circular dependency is not accidentally reintroduced."
        echo
        EXIT_CODE=1
    fi
done

exit ${EXIT_CODE}
