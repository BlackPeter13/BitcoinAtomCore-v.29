// Copyright (c) 2026 The Atom Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_RPC_MINTING_H
#define BITCOIN_WALLET_RPC_MINTING_H

#include <rpc/util.h>

namespace wallet {

::RPCHelpMan listminting();
::RPCHelpMan startstaking();
::RPCHelpMan stopstaking();
} // namespace wallet

#endif // BITCOIN_WALLET_RPC_MINTING_H
