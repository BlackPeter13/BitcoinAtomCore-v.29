# BCA patch inventory — bitcoin-atom (master, 0.16-based) vs upstream bitcoin v0.16.2
Method: `git diff upstream-v0.16.2 HEAD` (true upstream tag fetched from
bitcoin/bitcoin; the repo's own v0.16.2 tag is on the forked history).
Test-scope changes (dev.Dockerfile, difficulty float64) stashed separately,
NOT part of this inventory.

## Scale
- 368 files changed, +37112 / -69744 in src/ (bulk is deleted .ts
  translations + regenerated .ui/forms + seeds header — not logic).

## New files (BCA additions)
- `src/kernel.cpp` / `src/kernel.h` (387/31 lines) — PoS stake modifier,
  CheckStakeKernelHash, CheckProofOfStake, checkpoints. Peercoin-derived.
- `src/uint256hm.h` (148) — hash helper for kernel.
- `src/rpc/minting.cpp` (136) — `listminting` wallet RPC (mintable outputs).
- `src/rpc/swap.cpp` (699) — HTLC atomic-swap RPCs (contract/refund/redeem tx
  construction).
- `src/rpc/kernelrecord.cpp/h` (123) — staking record support for minting.
- `src/test/coinstake_tests.cpp` (323) — PoS unit tests.
- `src/test/data/script_tests.json.forkid` — forkid script test vectors.
- `src/qt/`: mainmenupanel, pricewidget (+stockinfo), lastsendtransactionview,
  changefeedialog (.cpp/.h/.ui), res/ Atom icons + RobotoMono fonts.

## Deleted (upstream files BCA dropped)
- `src/qt/locale/bitcoin_*.ts` (~30 translation files — regenerable, skip).
- `src/qt/test/Makefile`, `src/test/Makefile`, `src/test/validation_block_tests.cpp`,
  `src/univalue/gen/gen.cpp` (check against 29.x tree; likely obsolete there too).

## Modified — consensus / chain (Phase 2)
- `src/consensus/params.h` (+24): BCAHeight, BCAInitLim,
  NewDifficultyAdjustmentAlgoHeight, powLimitStart, PoS params
  (nPosTargetSpacing/Timespan, nStakeModifierInterval, nStakeMinAge/MaxAge,
  nInitialHashTargetPoS), nPowAveragingWindow, BitcoinPostforkBlock/Time.
- `src/chainparams.h` (+19): pchMessageStartLegacy, nBitcoinDefaultPort,
  vBootstrapSeeds / vFixedBootstrapSeeds, fMiningRequiresPeers,
  isLegacyBlock(), BitcoinAddressFormatParams().
- `src/chainparams.cpp` (+147/-44): networks, genesis, seeds, prefixes.
- `src/primitives/block.h` (+60): BLOCK_PROOF_OF_STAKE / _ENTROPY /
  _MODIFIER / _NEW_FORMAT flags, stake fields on header/block.
- `src/primitives/block.cpp` (+17), `transaction.h` (+14), `coins.h` (+18).
- `src/chain.h` (+94/-5): nPowHeight, stake modifier fields, IsProofOfStake().
- `src/chain.cpp` (+31).
- `src/pow.h`, `src/pow.cpp` (+140/-13): GetNextWorkRequired(...,bool fProofOfStake),
  GetLastBlockIndex, new PoW averaging-window DA + legacy retarget path.
- `src/validation.h` (+14/-7), `src/validation.cpp` (+339/-103): BCAHeight
  activation gates, CheckBlock PoS rejection window, ConnectBlock coinstake
  rules (fee, coin age, pay limits), stake modifier checkpoints, IBD skip near fork.
- `src/validationinterface.cpp` (+43/-33).
- `src/miner.cpp` (+207/-11): coinstake assembly into block template.
- `src/net_processing.cpp` (+154/-75), `src/net.cpp` (+15/-11): legacy/bootstrap peer logic.
- `src/script/interpreter.cpp` (+43/-33), `interpreter.h` (+17/-1),
  `sign.cpp` (+19/-1): SIGHASH_FORKID handling (replay protection).
- `src/script_tests.cpp` (+233/-61) + forkid vectors.
- `src/init.cpp` (+28/-21), `src/util.cpp` (+31/-9).

## Modified — wallet (Phase 3)
- `src/wallet/wallet.cpp` (+443/-24), `wallet.h` (+27/-11): staking/minting,
  coin-age selection.
- `src/wallet/rpcwallet.cpp` (+51/-29), `src/wallet/init.cpp` (+19/-5).

## Modified — RPC (Phase 4)
- `src/rpc/blockchain.cpp` (+70/-43): difficulty as {proof-of-work,
  proof-of-stake} object — rework to float64 + difficulty_pos (pool compat).
- `src/rpc/misc.cpp` (+96/-13), `mining.cpp` (+28/-11),
  `rawtransaction.cpp` (+35/-13), `bitcoin-cli.cpp` (+34/-15).

## Modified — GUI (Phase 4)
- New Atom panels wired via `src/Makefile.qt.include` (+94/-134),
  `src/qt/bitcoin.qrc` (+40); touched: sendcoinsdialog (+308),
  overviewpage, bitcoingui, transactionview, walletframe, walletmodel,
  coincontroldialog, walletview, receivecoinsdialog, guiutil, bitcoinunits.
- Strategy: port new-panel file set + .qrc/.ui wiring; keep upstream 29.x
  dialogs unless BCA logic delta requires merging.

## Base
- Branch `rebase/core29` == upstream `v29.3` (99003be). CMake build,
  depends/ has qt.mk + bdb.mk. System Qt5 per doc/build-unix.md.

## Port status (live)
- Done: consensus params/chainparams/block+index/PoW+PoS retarget/stake
  kernel/validation PoS/CheckBlock/headers/Coin nTime/fork-id
  sighash+signing/miner PoS assembly/SignBlock/net dual-magic/init args/RPC
  (difficulty_pos, block PoS fields, hashps, submitblock legacy,
  getblocktemplate proposal, convertaddress, mintonly, getwalletinfo
  mintonly, sighash FORKID default+enforcement)/units BCA branding/
  CreateCoinStake (legacy wallets)/minter assembly (thread deferred).
- Verified: stock v29.3 builds; regtest node runs; legacy BDB wallet
  create/load needs `-deprecatedrpc=create_bdb`; rescanblockchain +
  scantxoutset sane.
- Deferred: swap/minting/kernelrecord RPCs (0.16 wallet APIs need 29.x
  rewrite), PeerManager bootstrap sync, Qt redesign (branding only),
  descriptor-wallet staking, minter background thread.
