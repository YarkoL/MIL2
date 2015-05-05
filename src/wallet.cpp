// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txdb.h"
#include "wallet.h"
#include "walletdb.h"
#include "crypter.h"
#include "ui_interface.h"
#include "base58.h"
#include "kernel.h"
#include "coincontrol.h"
#include "delegatemanager.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/lexical_cast.hpp>


using namespace std;
extern unsigned int nStakeMaxAge;

unsigned int nStakeSplitAge = 1 * 24 * 60 * 60;
int64_t nStakeCombineThreshold = 1000 * COIN;

//////////////////////////////////////////////////////////////////////////////
//
// mapWallet
//

struct CompareValueOnly
{
    bool operator()(const pair<int64_t, pair<const CWalletTx*, unsigned int> >& t1,
                    const pair<int64_t, pair<const CWalletTx*, unsigned int> >& t2) const
    {
        return t1.first < t2.first;
    }
};


static bool GetBoundAddress(
    CWallet* wallet,
    uint160 const& hash,
    CNetAddr& address
) {
    std::set<
        std::pair<CNetAddr, uint64_t>
    > const& address_binds = wallet->get_address_binds();
    for (
        std::set<
            std::pair<CNetAddr, uint64_t>
        >::const_iterator checking = address_binds.begin();
        address_binds.end() != checking;
        checking++
    ) {
        if (
            hash == Hash160(
                CreateAddressIdentification(
                    checking->first,
                    checking->second
                )
            )
        ) {
            address = checking->first;
            return true;
        }
    }
    return false;
}

static bool ExtractKeyFromTx (CWallet* wallet, CTransaction tx, std::vector<unsigned char>& key) {
    uint160 hash;
    CNetAddr others_address;
    if (!GetBindHash(hash, tx)) return false;

    if (!wallet->get_hash_delegate(hash, key)) {
        if (!GetBoundAddress(wallet, hash, others_address))
            return false;
        return DelegateManager::getKeyFromOther(others_address, key);
    }
    return DelegateManager::keyExists(key);
}

//extract the txid of relayed transaction from confirmation messages scriptPubKey
static bool ExtractTxIdFromOut(CTransaction tx, uint256& relayed_tx_id) {

    if (tx.vout.empty()) return false;

    CTxOut const payload_output = tx.vout[0];
    CScript const payload = payload_output.scriptPubKey;
    opcodetype opcode;
    std::vector<unsigned char> data;

    CScript::const_iterator position = payload.begin();
    if (position >= payload.end()) return false;

    if (!payload.GetOp(position, opcode, data)) return false;

    if (0 <= opcode && opcode <= OP_PUSHDATA4) {

        if (sizeof(relayed_tx_id) > data.size()) return false;
        memcpy(&relayed_tx_id, data.data(), sizeof(relayed_tx_id));
    } else {
        return false;
    }
    return true;
}

static bool ConfirmedTransactionSubmit(
    CTransaction sent_tx,
    CTransaction& confirming_tx
) {
    uint256 const tx_hash = sent_tx.GetHash();
    CTxDB txdb("r");

    if (!sent_tx.AcceptToMemoryPool(txdb, true)) {
        return false;
    }
    SyncWithWallets(sent_tx, NULL, true);
    RelayTransaction(sent_tx, tx_hash);

    CTransaction confirmTx;

    CTxOut confirm_transfer;

    confirm_transfer.scriptPubKey = CScript() << tx_hash;

    confirmTx.vout.push_back(confirm_transfer);

    confirming_tx = confirmTx;
    return true;
}


static bool ProcessOffChain(
    CWallet* wallet,
    std::string const& name,
    CTransaction const& tx,
    int64_t timeout
) {
    if ("request-delegate" == name ) {
        if (tx.vout.empty()) {
            return false;
        }
        //delegate extracts info from the initial message from sender
        CTxOut const payload_output = tx.vout[0];
        CScript const payload = payload_output.scriptPubKey;
        opcodetype opcode;
        std::vector<unsigned char> data;

        //read join-nonce
        uint64_t join_nonce;
        CNetAddr sender_address;
        CScript::const_iterator position = payload.begin();
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (sizeof(join_nonce) > data.size()) {
                return false;
            }
            memcpy(&join_nonce, data.data(), sizeof(join_nonce));
        } else {
            return false;
        }

        //read sender Tor address
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            std::vector<unsigned char> const unique( data.begin() + 6,data.end());
            if (!sender_address.SetSpecial(EncodeBase32(unique.data(), unique.size()) + ".onion")) {
                return false;
            }
        } else {
            return false;
        }

        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            CTransaction response_tx;

            CTxOut response_txout;

            uint64_t const sender_address_bind_nonce = GetRand(std::numeric_limits<uint64_t>::max());

            //data here is sender's key to delegate map
            response_txout.scriptPubKey = CScript() << data << sender_address_bind_nonce;

            response_tx.vout.push_back(response_txout);

            PushOffChain(sender_address, "confirm-delegate", response_tx);

            //add to delegate map
            CNetAddr const local = GetLocalTorAddress(sender_address);
            std::vector<unsigned char> const key = DelegateManager::store( true,
                                                                           local,
                                                                           sender_address,
                                                                           CScript(position, payload.end()),
                                                                           payload_output.nValue
                                                                           );

            wallet->store_address_bind(sender_address, sender_address_bind_nonce);
            wallet->store_join_nonce_delegate(join_nonce, key);

            CTransaction delegate_identification_request;

            CTxOut request_transfer;
            request_transfer.scriptPubKey = CScript() << data << key;

            delegate_identification_request.vout.push_back(request_transfer);

            PushOffChain(
                sender_address,
                "request-delegate-identification",
                delegate_identification_request
            );
        } else return false;
        return true;
      } else if ("request-delegate-identification" == name ) {

     if (tx.vout.empty())
        return false;

     CTxOut const payload_output = tx.vout[0];
     CScript const payload = payload_output.scriptPubKey;
     opcodetype opcode;

     //get key
     std::vector<unsigned char> key;
     std::vector<unsigned char> data;
     CNetAddr delegate_address;

     CScript::const_iterator position = payload.begin();
     if (position >= payload.end()) {
         return false;
     }
     if (!payload.GetOp(position, opcode, data)) {
         return false;
     }
     if (0 <= opcode && opcode <= OP_PUSHDATA4) {
             key = data;
             if (!DelegateManager::keyExists(key))
                 return false;
             if (DelegateManager::isDelegate(key))
                 return false;
             delegate_address = DelegateManager::other(key);
         } else {
            return false;
         }
         if (position >= payload.end()) {
             return false;
         }
         if (!payload.GetOp(position, opcode, data)) {
             return false;
         }
         if (0 <= opcode && opcode <= OP_PUSHDATA4) {
              CTransaction response_tx;

              CTxOut response_data_txout;

              uint64_t const delegate_address_bind_nonce = GetRand(std::numeric_limits<uint64_t>::max());

              wallet->store_address_bind(delegate_address, delegate_address_bind_nonce);

              response_data_txout.scriptPubKey = CScript() << data << delegate_address_bind_nonce;

              response_tx.vout.push_back(response_data_txout);

              PushOffChain(delegate_address, "confirm-sender", response_tx);
              return true;
          } else
             return false;

    } else if ("confirm-delegate" == name || "confirm-sender" == name) {
        if (tx.vout.empty()) {
            return false;
        }

        CTxOut const payload_output = tx.vout[0];
        CScript const payload = payload_output.scriptPubKey;
        opcodetype opcode;

        //get key
        std::vector<unsigned char> key;
        std::vector<unsigned char> data;

        CScript::const_iterator position = payload.begin();
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            key = data;

        } else {
            return false;
        }
        if (!DelegateManager::keyExists(key))
            return false;

        //get other's ABM
        if (position >= payload.end()) {
            return false;
        }
        if (!payload.GetOp(position, opcode, data)) {
            return false;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            uint64_t address_bind_nonce;
            if (sizeof(address_bind_nonce) > data.size()) {
                return false;
            }
            memcpy(&address_bind_nonce, data.data(), sizeof(address_bind_nonce));

            InitializeBind(
                        key,
                        address_bind_nonce,
                        DelegateManager::self(key),
                        DelegateManager::other(key),
                        DelegateManager::amount(key),
                        DelegateManager::isDelegate(key)
                        );

            wallet->store_delegate_nonce(address_bind_nonce, key);
            return true;
        } else
            return false;

    } else if  ("to-sender" == name || "to-delegate" == name) {

        std::vector<unsigned char> key;
       // if (!ExtractKeyFromTx(wallet, tx,  key)) //bug
       //     return false;

        uint160 hash;
        CNetAddr others_address;
        if (!GetBindHash(hash, tx)) return false;

        if (!GetBoundAddress(wallet, hash, others_address)) return false;

        if (!DelegateManager::getKeyFromOther(others_address, key)) return false;

        CTransaction merged_tx = tx;
        CPubKey signing_key;
        do {
            CReserveKey reserve_key(wallet);
            if (!reserve_key.GetReservedKeyIn(signing_key)) {
                throw std::runtime_error("could not find signing address");
            }
        } while (false);

        CBitcoinAddress signing_address;

        signing_address.Set(signing_key.GetID());

        bool is_delegate = DelegateManager::isDelegate(key);

        SignBind(wallet, merged_tx, signing_address, is_delegate);

        PushOffChain(
            others_address,
            is_delegate ? "request-sender-funding" : "request-delegate-funding",
            merged_tx
        );

        return true;
    } else if ("request-sender-funding" == name || "request-delegate-funding" == name) {

        std::vector<unsigned char> key;
        if (!ExtractKeyFromTx(wallet, tx,  key))
            return false;

        bool is_delegate = DelegateManager::isDelegate(key);

        if(!is_delegate) {
            //read delegate's public keyhash from the bindtx and replace the destination in map with it
            CKeyID delegatePKH;
            if (!GetPubKeyHash(delegatePKH, tx, is_delegate)) {
                return false;
            }
            CTxDestination const delegate_destination(delegatePKH);
            CScript payment_script;
            payment_script.SetDestination(delegate_destination);
            if (!DelegateManager::setDestination(key, payment_script)) {
                return false;
            }
        }

        CTransaction const funded_tx = FundAddressBind(wallet, tx);

        std::string funded_txid = funded_tx.GetHash().ToString();

        if(!is_delegate) {
            //SENDRET2
            uint64_t nonce;
            if (!wallet->get_delegate_nonce(nonce, key)) {
                printf("Could not get nonce while processing request-sender-funding");
            }
            wallet->add_to_retrieval_string_in_nonce_map(nonce, funded_txid,false);
            if (fDebug) printf("Added to sender retrieval string at nonce %"PRIu64" funded tx id %s \n",
                       nonce,  funded_txid.c_str());

            std::string retrieve;
            if (!wallet->read_retrieval_string_from_nonce_map(nonce, retrieve, false)) {
               printf("Could not get retrieve string for nonce %"PRIu64" while processing confirm-sender-bind\n",
               nonce);
            } else {
                if (wallet->StoreRetrieveStringToDB(funded_tx.GetHash(), retrieve, false)) {
                    if (fDebug) printf("Wrote retrieve string for txid %s while processing confirm-sender-bind\n with contents: %s\n",
                                     funded_txid.c_str(), retrieve.c_str());
                } else {
                    printf("Could not set retrieve string for txid %s while processing confirm-sender-bind\n",
                            funded_txid.c_str());
                }
            }

          }
        PushOffChain(
            DelegateManager::other(key),
            is_delegate? "funded-delegate-bind" : "funded-sender-bind",
            funded_tx
            );
         return true;

    }  else if ("funded-sender-bind" == name || "funded-delegate-bind" == name) {

        std::vector<unsigned char> key;
        if (!ExtractKeyFromTx(wallet, tx,  key)) return false;

        CNetAddr others_address = DelegateManager::other(key);

        CTransaction confirmTx;
        if (!ConfirmedTransactionSubmit(tx, confirmTx)) {
            return false;
        }
        bool is_delegate = DelegateManager::isDelegate(key);
        if (is_delegate) {
            //DELRET 2 store sender bind tx id
            uint256 const sender_funded_tx_hash = tx.GetHash();
            uint64_t sender_address_bind_nonce;

            if(!wallet->GetBoundNonce(others_address, sender_address_bind_nonce)) {
                printf("ProcessOffChain() : committed-transfer: could not find sender_address_bind_nonce in address binds \n");
                return false;
            }

            wallet->add_to_retrieval_string_in_nonce_map(sender_address_bind_nonce, sender_funded_tx_hash.ToString(), true);
            printf("ProcessOffChain() : stored funded_tx_hash to retrieve string %s \n", sender_funded_tx_hash.ToString().c_str());

            //store the nonce to be replaced by delegate commit tx next stage of preparing retrieval string
            std::string retrieval;
            retrieval += boost::lexical_cast<std::string>(sender_address_bind_nonce);
            if(!wallet->StoreRetrieveStringToDB(sender_funded_tx_hash, retrieval, true)){
                printf("ProcessOffChain(): funded-sender-bind processing (delret 2): failed to set retrieve string \n");
            } else {
                printf("stored retrieval, txid : %s sender_address_bind_nonce %s\n", sender_funded_tx_hash.ToString().c_str(), retrieval.c_str());
            }

        }

        PushOffChain(others_address,
                     is_delegate ? "confirm-sender-bind" : "confirm-delegate-bind",
                     confirmTx);
        return true;
    } else if ("confirm-sender-bind" == name || "confirm-delegate-bind" == name ) {

        uint256 tx_id;
        if (!ExtractTxIdFromOut(tx, tx_id)) return false;

        //see if the relayed escrow is in block
        CTransaction escrowTx;
        uint256 hashBlock = 0;
        if (!GetTransaction(tx_id, escrowTx, hashBlock) || hashBlock == 0) {
            wallet->push_deferred_off_chain_transaction(
                timeout,
                name,
                tx
            );
            return true;
        }
        //escrowTx is in block
        std::vector<unsigned char> key;
        if(!ExtractKeyFromTx(wallet, escrowTx, key)) return false;

        if (!DelegateManager::isDelegate(key)) {
            wallet->set_sender_bind(key, tx_id); //store the escrow id
            return true; //sender is done here
        }

        //delegate send to recipient
        uint64_t delegate_address_bind_nonce;
        if (!wallet->get_delegate_nonce(delegate_address_bind_nonce, key)) {
            return false;
        }

        uint64_t const transfer_nonce = GetRand(std::numeric_limits<uint64_t>::max());

        CNetAddr sender_address = DelegateManager::other(key);
        CNetAddr local_address = DelegateManager::self(key);

        CTransaction commit_tx = CreateTransferCommit(
            wallet,
            tx_id,
            local_address,
            delegate_address_bind_nonce,
            transfer_nonce,
            DelegateManager::destination(key)
        );

        if (commit_tx.vout.empty()) {
            return false;
        }

        //DELRET 3
        std::string retrieval_data;
        uint64_t sender_address_bind_nonce;

        if(!wallet->GetBoundNonce(sender_address, sender_address_bind_nonce)) {
            printf("ProcessOffChain() : committed-transfer: could not find nonce in address binds \n");
            return false;
        }

        retrieval_data += sender_address.ToStringIP();
        retrieval_data += " ";
        retrieval_data += boost::lexical_cast<std::string>(sender_address_bind_nonce);
        retrieval_data += " ";
        retrieval_data += boost::lexical_cast<std::string>(transfer_nonce);
        retrieval_data += " ";
        retrieval_data += commit_tx.GetHash().ToString();

        wallet->add_to_retrieval_string_in_nonce_map(sender_address_bind_nonce, retrieval_data, true);
        printf("ProcessOffChain() : wrote sender address + nonces + committx_id to retrieve string %s \n", retrieval_data.c_str());

        std::string retrieval;
        wallet->read_retrieval_string_from_nonce_map(sender_address_bind_nonce, retrieval, true);

        if(!wallet->StoreRetrieveStringToDB(tx_id, retrieval, true)){
            printf("ProcessOffChain(): confirm-transfer processing: failed to set retrieve string \n");
        } else {
            printf("stored retrieval, txid : %s string: %s\n", tx_id.ToString().c_str(), retrieval_data.c_str());
        }
        wallet->ReplaceNonceWithRelayedDelegateTxHash(sender_address_bind_nonce, tx_id);
        //end delret

        PushOffChain(
            sender_address,
            "committed-transfer",
            commit_tx
        );
        return true;
    }  else if ("committed-transfer" == name) {

        //sender checks the delegates commit tx
        CTransaction commit_tx = tx;
        if (commit_tx.vout.empty() || commit_tx.vin.empty())  {
            return false;
        }
        //re-check that the escrow tx (input of commit) is confirmed
        CTransaction escrowTx;
        uint256 hashBlock = 0;
        if (!GetTransaction(commit_tx.vin[0].prevout.hash, escrowTx, hashBlock) || hashBlock == 0) {
            wallet->push_deferred_off_chain_transaction(
                timeout,
                name,
                tx
            );
            return true;
        }
        //ok, relay the commit tx and push txid to delegate
        std::vector<unsigned char> key;
        if(!ExtractKeyFromTx(wallet, escrowTx, key)) return false;

        CNetAddr delegate_address = DelegateManager::other(key);

        CTransaction confirmTx;
        if (!ConfirmedTransactionSubmit(commit_tx, confirmTx)) {
            return false;
        }
        if (confirmTx.vout.empty()) {
            return false;
        }

        PushOffChain(delegate_address, "confirm-transfer", confirmTx);

        //get back the txid of the relayed committed_tx
        uint256 committed_tx_id;
        if (!ExtractTxIdFromOut(confirmTx, committed_tx_id)) return false;

        //is the committed_tx confirmed?
        CTransaction committed_tx;
        hashBlock == 0;
        if (!GetTransaction(committed_tx_id, committed_tx, hashBlock) || hashBlock == 0) {
            wallet->push_deferred_off_chain_transaction(
                timeout,
                name,
                tx
            );
            return true;
        }
        //re-check that the escrow is confirmed
        if (committed_tx.vin.empty()) {
            return false;
        }
        if (!GetTransaction(committed_tx.vin[0].prevout.hash, escrowTx, hashBlock) || hashBlock == 0) {
            return false;
        }

        //just check the pubkey
        CKeyID pkh;
        if (!GetPubKeyHash(pkh, escrowTx, DelegateManager::isDelegate(key))) {
            return false;
        }

        uint256 funded_tx_id;
        if (!wallet->get_sender_bind(key, funded_tx_id)) {
            return false;
        }
        CTransaction const finalization_tx = CreateTransferFinalize(
            wallet,
            funded_tx_id,
            DelegateManager::destination(key) //this ought to be now delegates pubkey
        );
        PushOffChain(
            DelegateManager::other(key),
            "finalized-transfer",
            finalization_tx
        );

        //SENDRET-delete

       uint64_t nonce;

        if (!wallet->get_delegate_nonce(nonce, key)) {
            printf("Could not get nonce while processing committed-transfer");
            return true;
        }

        uint256 hash;
        if (!wallet->get_hash_from_expiry_nonce_map(nonce, hash)) {
             printf("Could not get tx hash for nonce %"PRIu64" while processing committed-transfer", nonce);
             return true;
        }

        if (!wallet->DeleteRetrieveStringFromDB(hash)){
            printf("Could not delete retrieve string for tx id %s \n",
                   hash.ToString().c_str());
                   return true;

        } else if (fDebug) printf("Deleted retrieve string for tx id %s",
                   hash.ToString().c_str());
        //delete delegate data
        DelegateManager::remove(key);
        return true;
    } else if ("confirm-transfer" == name) {

        //delegate does checking
        uint256 committed_txid;
        if(!ExtractTxIdFromOut(tx, committed_txid)) return false;

        uint256 hashBlock = 0;
        CTransaction committed_tx;
        if (!GetTransaction(committed_txid, committed_tx, hashBlock) || hashBlock == 0) {
            wallet->push_deferred_off_chain_transaction(
                timeout,
                name,
                tx
            );
            return true;
        }

        if (committed_tx.vin.empty()) {
            return false;
        }

        uint256 escrowTxID = committed_tx.vin[0].prevout.hash;

        CTransaction escrowTx;
        if (!GetTransaction(escrowTxID, escrowTx, hashBlock) || hashBlock == 0) {
            return false;
        }

        std::vector<unsigned char> key;
        if (!ExtractKeyFromTx(wallet, escrowTx, key)) return false;
        bool is_delegate = DelegateManager::isDelegate(key);
        if (!is_delegate) return false;

        CKeyID pkh;
        if (!GetPubKeyHash(pkh, escrowTx, is_delegate)) {
            return false;
        }
        return true;

    } else if ( "finalized-transfer" == name) {
        //delegate relays the finalized tx that pays to him. The end.
        CTransaction confirmTx;
        if (!ConfirmedTransactionSubmit(tx, confirmTx)) {
            return false;
        }
        //delete retrieval string
        uint256 sender_funded_tx = tx.vin[0].prevout.hash;
        std::string relayed_delegate_tx_id;

        if (wallet->ReadRetrieveStringFromHashMap(sender_funded_tx, relayed_delegate_tx_id, true)) {
            uint256 relayed_delegate_hash = uint256(relayed_delegate_tx_id);
            //as transfer has been finalized, we no longer need to retrieve
            wallet->DeleteRetrieveStringFromDB(relayed_delegate_hash);
            wallet->DeleteRetrieveStringFromDB(sender_funded_tx);
            //TODO: get key
            // DelegateManager::remove(key);
        }
        return true;
    }
 }


CTransaction FundAddressBind(CWallet* wallet, CTransaction unfundedTx) {
    CWalletTx fundedTx;

    CReserveKey reserve_key(wallet);

    int64_t fee = 0;

    CCoinControl coin_control;

    vector<pair<CScript, int64_t> > send_vector;

    for (
        vector<CTxOut>::iterator output = unfundedTx.vout.begin();
        unfundedTx.vout.end() != output;
        output++
    ) {
        send_vector.push_back(
            std::make_pair(output->scriptPubKey, output->nValue)
        );
    }

    if (
        !wallet->CreateTransaction(
            send_vector,
            fundedTx,
            reserve_key,
            fee,
            &coin_control
        )
    ) {
        throw runtime_error("fundaddressbind error ");
    }

    return fundedTx;
}


CPubKey CWallet::GenerateNewKey()
{
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    RandAddSeedPerfmon();
    CKey key;
    key.MakeNewKey(fCompressed);

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed)
        SetMinVersion(FEATURE_COMPRPUBKEY);

    CPubKey pubkey = key.GetPubKey();

    // Create new metadata
    int64_t nCreationTime = GetTime();
    mapKeyMetadata[pubkey.GetID()] = CKeyMetadata(nCreationTime);
    if (!nTimeFirstKey || nCreationTime < nTimeFirstKey)
        nTimeFirstKey = nCreationTime;

    if (!AddKey(key))
        throw std::runtime_error("CWallet::GenerateNewKey() : AddKey failed");
    return key.GetPubKey();
}

bool CWallet::AddKey(const CKey& key)
{
    CPubKey pubkey = key.GetPubKey();

    if (!CCryptoKeyStore::AddKey(key))
        return false;
    if (!fFileBacked)
        return true;
    if (!IsCrypted())
        return CWalletDB(strWalletFile).WriteKey(pubkey, key.GetPrivKey(), mapKeyMetadata[pubkey.GetID()]);
    return true;
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey, const vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
        else
            return CWalletDB(strWalletFile).WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
    }
    return false;
}

bool CWallet::LoadKeyMetadata(const CPubKey &pubkey, const CKeyMetadata &meta)
{
    if (meta.nCreateTime && (!nTimeFirstKey || meta.nCreateTime < nTimeFirstKey))
        nTimeFirstKey = meta.nCreateTime;

    mapKeyMetadata[pubkey.GetID()] = meta;
    return true;
}

bool CWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

bool CWallet::AddCScript(const CScript& redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteCScript(Hash160(redeemScript), redeemScript);
}

// optional setting to unlock wallet for staking only
// serves to disable the trivial sendmoney when OS account compromised
// provides no real security
bool fWalletUnlockStakingOnly = false;

bool CWallet::Unlock(const SecureString& strWalletPassphrase)
{
    if (!IsLocked())
        return false;

    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
                return true;
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        BOOST_FOREACH(MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
            {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                printf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }
    return false;
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
    CWalletDB walletdb(strWalletFile);
    walletdb.WriteBestBlock(loc);
}

void CWallet::store_hash_delegate(
    uint160 const& hash,
    std::vector<unsigned char> const& key
) {
    hash_delegates[hash] = key;
}

bool CWallet::get_delegate_nonce(
    uint64_t& nonce,
    std::vector<unsigned char> const& key
) {
    if (delegate_nonces.end() == delegate_nonces.find(key)) {
        return false;
    }
    nonce = delegate_nonces.at(key);
    return true;
}

//retrieval functions

void CWallet::add_to_retrieval_string_in_nonce_map(uint64_t& nonce, string const& retrieve, bool isEscrow) {
    isEscrow ? mapEscrow[nonce].push_back(retrieve) : mapExpiry[nonce].push_back(retrieve);
}

bool CWallet::get_hash_from_expiry_nonce_map(const uint64_t nonce, uint256 &hash)
{
    if (mapExpiry.end() == mapExpiry.find(nonce)) {
        return false;
    }
    std::list<std::string> value = mapExpiry.at(nonce);
    hash = uint256(value.back());
    return true;
}

bool CWallet::read_retrieval_string_from_nonce_map(uint64_t const& nonce, std::string& retrieve, bool isEscrow) {
    if (isEscrow) {
          map<uint64_t, std::list<std::string> >::iterator it = mapEscrow.find(nonce);
          if (it != mapEscrow.end()) {
               std::list<std::string> retrievalstrings = (*it).second;
               for ( std::list<std::string>::const_iterator str = retrievalstrings.begin() ; str != retrievalstrings.end(); ++str) {
                   retrieve += *str + " ";
               }
               /* //write to db
               mapEscrowRetrieve[hash] = retrieve;
               return CWalletDB(strWalletFile).WriteRetrieveString(hash, retrieve);
               */
               return true;
          }
    } else {
        map<uint64_t, std::list<std::string> >::iterator it = mapExpiry.find(nonce);
        if (it != mapExpiry.end()) {
             std::list<std::string> retrievalstrings = (*it).second;
             for ( std::list<std::string>::const_iterator str = retrievalstrings.begin() ; str != retrievalstrings.end(); ++str) {
                 retrieve += *str + " ";
             }
             /*
             mapExpiryRetrieve[hash] = retrieve;
             return CWalletDB(strWalletFile).WriteExpiryRetrieveString(hash, retrieve);
             */
             return true;
        }
    }
    return false;
}

bool CWallet::ReadRetrieveStringFromHashMap(const uint256 &hash, std::string &retrieve, bool isEscrow)
{
    if (isEscrow) {
        map<uint256,std::string>::iterator it = mapEscrowRetrieve.find(hash);
        if (it != mapEscrowRetrieve.end()) {
             retrieve = (*it).second;
             return true;
        }
    } else {
        map<uint256,std::string>::iterator it = mapExpiryRetrieve.find(hash);
        if (it != mapExpiryRetrieve.end()) {
             retrieve = (*it).second;
             return true;
        }
    }
    return false;
}

void CWallet::erase_retrieval_string_from_nonce_map(uint64_t const& nonce, bool isEscrow) {
    isEscrow? mapEscrow.erase(nonce) : mapExpiry.erase(nonce);
}

bool CWallet::IsRetrievable(const uint256 hash, bool isEscrow) {
    if (isEscrow)
        return (mapEscrowRetrieve.find(hash) != mapEscrowRetrieve.end());
    else
        return (mapExpiryRetrieve.find(hash) != mapExpiryRetrieve.end());
}

bool CWallet::clearRetrieveHashMap(bool isEscrow) {
   bool erased;
    if (isEscrow) {
       map<uint256,std::string>::iterator it = mapEscrowRetrieve.begin();
       while(it != mapEscrowRetrieve.end()) {
           erased = CWalletDB(strWalletFile).EraseRetrieveString(it->first);
           ++it;
       }
       mapEscrowRetrieve.clear();
   } else {
       map<uint256,std::string>::iterator it = mapExpiryRetrieve.begin();
       while(it != mapExpiryRetrieve.end()) {
           erased = CWalletDB(strWalletFile).EraseExpiryRetrieveString(it->first);
           ++it;
       }
       mapExpiryRetrieve.clear();
   }
   return erased;
}

bool CWallet::StoreRetrieveStringToDB(const uint256 hash, const string& retrieve, bool isEscrow)
{
   if (isEscrow) {
       mapEscrowRetrieve[hash] = retrieve;
       return CWalletDB(strWalletFile).WriteRetrieveString(hash, retrieve);
   }
   mapExpiryRetrieve[hash] = retrieve;
   return CWalletDB(strWalletFile).WriteExpiryRetrieveString(hash, retrieve);
}

bool CWallet::DeleteRetrieveStringFromDB(const uint256 hash)
{
    bool eraseExpiry, eraseEscrow;
    mapExpiryRetrieve.erase(hash);
    eraseExpiry = CWalletDB(strWalletFile).EraseExpiryRetrieveString(hash);
    mapEscrowRetrieve.erase(hash);
    eraseEscrow = CWalletDB(strWalletFile).EraseRetrieveString(hash);
    return (eraseExpiry || eraseEscrow);
}

bool CWallet::ReplaceNonceWithRelayedDelegateTxHash(uint64_t nonce, uint256 hash) {
    bool found = false;
    std::string nonce_str = boost::lexical_cast<std::string>(nonce);

    map<uint256,std::string>::iterator it = mapEscrowRetrieve.begin();
    while(it != mapEscrowRetrieve.end()) {
        found = (it->second == nonce_str);
        if(found) {
            it->second = hash.ToString();
             break;
        }
        ++it;
    }
    return found;
}


void CWallet::store_address_bind(CNetAddr const& address, uint64_t const& nonce) {
    address_binds.insert(std::make_pair(address, nonce));
}

std::set<std::pair<CNetAddr, uint64_t> >& CWallet::get_address_binds() {
    return address_binds;
}

bool CWallet::get_hash_delegate(
    uint160 const& hash,
    std::vector<unsigned char>& key
) {
    if (hash_delegates.end() == hash_delegates.find(hash)) {
        return false;
    }
    key = hash_delegates.at(hash);
    return true;
}

// This class implements an addrIncoming entry that causes pre-0.4
// clients to crash on startup if reading a private-key-encrypted wallet.
class CCorruptAddress
{
public:
    IMPLEMENT_SERIALIZE
    (
        if (nType & SER_DISK)
            READWRITE(nVersion);
    )
};

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB* pwalletdbIn, bool fExplicit)
{
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
            nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked)
    {
        CWalletDB* pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(strWalletFile);
        if (nWalletVersion >= 40000)
        {
            // Versions prior to 0.4.0 did not support the "minversion" record.
            // Use a CCorruptAddress to make them crash instead.
            CCorruptAddress corruptAddress;
            pwalletdb->WriteSetting("addrIncoming", corruptAddress);
        }
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion)
{
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial vMasterKey;
    RandAddSeedPerfmon();

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    RAND_bytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey(nDerivationMethodIndex);

    RandAddSeedPerfmon();
    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    RAND_bytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    printf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked)
        {
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            if (!pwalletdbEncryption->TxnBegin())
                return false;
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(vMasterKey))
        {
            if (fFileBacked)
                pwalletdbEncryption->TxnAbort();
            exit(1); //We now probably have half of our keys encrypted in memory, and half not...die and let the user reload their unencrypted wallet.
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (fFileBacked)
        {
            if (!pwalletdbEncryption->TxnCommit())
                exit(1); //We now have keys encrypted in memory, but no on disk...die to avoid confusion and let the user reload their unencrypted wallet.

            delete pwalletdbEncryption;
            pwalletdbEncryption = NULL;
        }

        Lock();
        Unlock(strWalletPassphrase);
        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile);

    }
    NotifyStatusChanged(this);

    return true;
}

int64_t CWallet::IncOrderPosNext(CWalletDB *pwalletdb)
{
    int64_t nRet = nOrderPosNext++;
    if (pwalletdb) {
        pwalletdb->WriteOrderPosNext(nOrderPosNext);
    } else {
        CWalletDB(strWalletFile).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

CWallet::TxItems CWallet::OrderedTxItems(std::list<CAccountingEntry>& acentries, std::string strAccount)
{
    CWalletDB walletdb(strWalletFile);

    // First: get all CWalletTx and CAccountingEntry into a sorted-by-order multimap.
    TxItems txOrdered;

    // Note: maintaining indices in the database of (account,time) --> txid and (account, time) --> acentry
    // would make this much faster for applications that do this a lot.
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        CWalletTx* wtx = &((*it).second);
        txOrdered.insert(make_pair(wtx->nOrderPos, TxPair(wtx, (CAccountingEntry*)0)));
    }
    acentries.clear();
    walletdb.ListAccountCreditDebit(strAccount, acentries);
    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txOrdered.insert(make_pair(entry.nOrderPos, TxPair((CWalletTx*)0, &entry)));
    }

    return txOrdered;
}

void CWallet::WalletUpdateSpent(const CTransaction &tx, bool fBlock)
{
    // Anytime a signature is successfully verified, it's proof the outpoint is spent.
    // Update the wallet spent flag if it doesn't know due to wallet.dat being
    // restored from backup or the user making copies of wallet.dat.
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
        {
            map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
            if (mi != mapWallet.end())
            {
                CWalletTx& wtx = (*mi).second;
                if (txin.prevout.n >= wtx.vout.size())
                    printf("WalletUpdateSpent: bad wtx %s\n", wtx.GetHash().ToString().c_str());
                else if (!wtx.IsSpent(txin.prevout.n) && IsMine(wtx.vout[txin.prevout.n]))
                {
                    printf("WalletUpdateSpent found spent coin %s SUM %s\n", FormatMoney(wtx.GetCredit()).c_str(), wtx.GetHash().ToString().c_str());
                    wtx.MarkSpent(txin.prevout.n);
                    wtx.WriteToDisk();
                    NotifyTransactionChanged(this, txin.prevout.hash, CT_UPDATED);
                }
            }
        }

        if (fBlock)
        {
            uint256 hash = tx.GetHash();
            map<uint256, CWalletTx>::iterator mi = mapWallet.find(hash);
            CWalletTx& wtx = (*mi).second;

            BOOST_FOREACH(const CTxOut& txout, tx.vout)
            {
                if (IsMine(txout))
                {
                    wtx.MarkUnspent(&txout - &tx.vout[0]);
                    wtx.WriteToDisk();
                    NotifyTransactionChanged(this, hash, CT_UPDATED);
                }
            }
        }

    }
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
            item.second.MarkDirty();
    }
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    {
        LOCK(cs_wallet);
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        wtx.BindWallet(this);
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
        {
            wtx.nTimeReceived = GetAdjustedTime();
            wtx.nOrderPos = IncOrderPosNext();

            wtx.nTimeSmart = wtx.nTimeReceived;
            if (wtxIn.hashBlock != 0)
            {
                if (mapBlockIndex.count(wtxIn.hashBlock))
                {
                    unsigned int latestNow = wtx.nTimeReceived;
                    unsigned int latestEntry = 0;
                    {
                        // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                        int64_t latestTolerated = latestNow + 300;
                        std::list<CAccountingEntry> acentries;
                        TxItems txOrdered = OrderedTxItems(acentries);
                        for (TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
                        {
                            CWalletTx *const pwtx = (*it).second.first;
                            if (pwtx == &wtx)
                                continue;
                            CAccountingEntry *const pacentry = (*it).second.second;
                            int64_t nSmartTime;
                            if (pwtx)
                            {
                                nSmartTime = pwtx->nTimeSmart;
                                if (!nSmartTime)
                                    nSmartTime = pwtx->nTimeReceived;
                            }
                            else
                                nSmartTime = pacentry->nTime;
                            if (nSmartTime <= latestTolerated)
                            {
                                latestEntry = nSmartTime;
                                if (nSmartTime > latestNow)
                                    latestNow = nSmartTime;
                                break;
                            }
                        }
                    }

                    unsigned int& blocktime = mapBlockIndex[wtxIn.hashBlock]->nTime;
                    wtx.nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
                }
                else
                    printf("AddToWallet() : found %s in block %s not in index\n",
                           wtxIn.GetHash().ToString().substr(0,10).c_str(),
                           wtxIn.hashBlock.ToString().c_str());
            }
        }

        bool fUpdated = false;
        if (!fInsertedNew)
        {
            // Merge
            if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex))
            {
                wtx.vMerkleBranch = wtxIn.vMerkleBranch;
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
            fUpdated |= wtx.UpdateSpent(wtxIn.vfSpent);
        }

        //// debug print
        printf("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString().substr(0,10).c_str(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

        // Write to disk
        if (fInsertedNew || fUpdated)
            if (!wtx.WriteToDisk())
                return false;
#ifndef QT_GUI
        // If default receiving address gets used, replace it with a new one
        CScript scriptDefaultKey;
        scriptDefaultKey.SetDestination(vchDefaultKey.GetID());
        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            if (txout.scriptPubKey == scriptDefaultKey)
            {
                CPubKey newDefaultKey;
                if (GetKeyFromPool(newDefaultKey, false))
                {
                    SetDefaultKey(newDefaultKey);
                    SetAddressBookName(vchDefaultKey.GetID(), "");
                }
            }
        }
#endif
        // since AddToWallet is called directly for self-originating transactions, check for consumption of own coins
        WalletUpdateSpent(wtx, (wtxIn.hashBlock != 0));

        // Notify UI of new or updated transaction
        NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);

        // notify an external script when a wallet transaction comes in or is updated
        std::string strCmd = GetArg("-walletnotify", "");

        if ( !strCmd.empty())
        {
            boost::replace_all(strCmd, "%s", wtxIn.GetHash().GetHex());
            boost::thread t(runCommand, strCmd); // thread runs free
        }

    }
    return true;
}

// Add a transaction to the wallet, or update it.
// pblock is optional, but should be provided if the transaction is known to be in a block.
// If fUpdate is true, existing transactions will be updated.
bool CWallet::AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fFindBlock)
{
    uint256 hash = tx.GetHash();
    {
        LOCK(cs_wallet);
        bool fExisted = mapWallet.count(hash);
        if (fExisted && !fUpdate) return false;
        if (fExisted || IsMine(tx) || IsFromMe(tx))
        {
            CWalletTx wtx(this,tx);
            // Get merkle branch if transaction was found in a block
            if (pblock)
                wtx.SetMerkleBranch(pblock);
            return AddToWallet(wtx);
        }
        else
            WalletUpdateSpent(tx);
    }
    return false;
}

bool CWallet::EraseFromWallet(uint256 hash)
{
    if (!fFileBacked)
        return false;
    {
        LOCK(cs_wallet);
        if (mapWallet.erase(hash))
            CWalletDB(strWalletFile).EraseTx(hash);
    }
    return true;
}


bool CWallet::IsMine(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]))
                    return true;
        }
    }
    return false;
}

int64_t CWallet::GetDebit(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]))
                    return prev.vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

bool CWallet::IsChange(const CTxOut& txout) const
{
    CTxDestination address;

    txnouttype tx_type;
    vector<vector<unsigned char> > values;

    if (Solver(txout.scriptPubKey, tx_type, values)) {
        if (tx_type == TX_ESCROW_FEE || tx_type == TX_ESCROW_SENDER || tx_type == TX_ESCROW) {
            return false;
        }
    }

    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a TX_PUBKEYHASH that is mine but isn't in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (ExtractDestination(txout.scriptPubKey, address) && ::IsMine(*this, address))
    {
        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

int64_t CWalletTx::GetTxTime() const
{
    int64_t n = nTimeSmart;
    return n ? n : nTimeReceived;
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (IsCoinBase() || IsCoinStake())
        {
            // Generated block
            if (hashBlock != 0)
            {
                map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        }
        else
        {
            // Did anyone request this transaction?
            map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
            if (mi != pwallet->mapRequestCount.end())
            {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && hashBlock != 0)
                {
                    map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                    if (mi != pwallet->mapRequestCount.end())
                        nRequests = (*mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

void CWalletTx::GetAmounts(list<pair<CTxDestination, int64_t> >& listReceived,
                           list<pair<CTxDestination, int64_t> >& listSent, int64_t& nFee, string& strSentAccount) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Compute fee:
    int64_t nDebit = GetDebit();
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        int64_t nValueOut = GetValueOut();
        nFee = nDebit - nValueOut;
    }

    // Sent/received.
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        // Skip special stake out
        if (txout.scriptPubKey.empty())
            continue;

        bool fIsMine;
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
            fIsMine = pwallet->IsMine(txout);
        }
        else if (!(fIsMine = pwallet->IsMine(txout)))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
        {
            printf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                   this->GetHash().ToString().c_str());
            address = CNoDestination();
        }

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(make_pair(address, txout.nValue));

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine)
            listReceived.push_back(make_pair(address, txout.nValue));
    }

}

void CWalletTx::GetAccountAmounts(const string& strAccount, int64_t& nReceived,
                                  int64_t& nSent, int64_t& nFee) const
{
    nReceived = nSent = nFee = 0;

    int64_t allFee;
    string strSentAccount;
    list<pair<CTxDestination, int64_t> > listReceived;
    list<pair<CTxDestination, int64_t> > listSent;
    GetAmounts(listReceived, listSent, allFee, strSentAccount);

    if (strAccount == strSentAccount)
    {
        BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64_t)& s, listSent)
            nSent += s.second;
        nFee = allFee;
    }
    {
        LOCK(pwallet->cs_wallet);
        BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64_t)& r, listReceived)
        {
            if (pwallet->mapAddressBook.count(r.first))
            {
                map<CTxDestination, string>::const_iterator mi = pwallet->mapAddressBook.find(r.first);
                if (mi != pwallet->mapAddressBook.end() && (*mi).second == strAccount)
                    nReceived += r.second;
            }
            else if (strAccount.empty())
            {
                nReceived += r.second;
            }
        }
    }
}

void CWalletTx::AddSupportingTransactions(CTxDB& txdb)
{
    vtxPrev.clear();

    const int COPY_DEPTH = 3;
    if (SetMerkleBranch() < COPY_DEPTH)
    {
        vector<uint256> vWorkQueue;
        BOOST_FOREACH(const CTxIn& txin, vin)
            vWorkQueue.push_back(txin.prevout.hash);

        // This critsect is OK because txdb is already open
        {
            LOCK(pwallet->cs_wallet);
            map<uint256, const CMerkleTx*> mapWalletPrev;
            set<uint256> setAlreadyDone;
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hash = vWorkQueue[i];
                if (setAlreadyDone.count(hash))
                    continue;
                setAlreadyDone.insert(hash);

                CMerkleTx tx;
                map<uint256, CWalletTx>::const_iterator mi = pwallet->mapWallet.find(hash);
                if (mi != pwallet->mapWallet.end())
                {
                    tx = (*mi).second;
                    BOOST_FOREACH(const CMerkleTx& txWalletPrev, (*mi).second.vtxPrev)
                        mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
                }
                else if (mapWalletPrev.count(hash))
                {
                    tx = *mapWalletPrev[hash];
                }
                else if (!fClient && txdb.ReadDiskTx(hash, tx))
                {
                    ;
                }
                else
                {
                    printf("ERROR: AddSupportingTransactions() : unsupported transaction\n");
                    continue;
                }

                int nDepth = tx.SetMerkleBranch();
                vtxPrev.push_back(tx);

                if (nDepth < COPY_DEPTH)
                {
                    BOOST_FOREACH(const CTxIn& txin, tx.vin)
                        vWorkQueue.push_back(txin.prevout.hash);
                }
            }
        }
    }

    reverse(vtxPrev.begin(), vtxPrev.end());
}

bool CWalletTx::WriteToDisk()
{
    return CWalletDB(pwallet->strWalletFile).WriteTx(GetHash(), *this);
}

bool CWalletTx::IsAnonSpent(const int n) const {
    CTxDB txdb("r");
    uint256 hashTx = this->GetHash();
    CTxIndex txIndex;
    if (txdb.ReadTxIndex(hashTx, txIndex)) {
       if (!txIndex.vSpent[n].IsNull()) {
            return true;
       }
    } else {
       //not indexed, shouldn't happen
        printf("Found missing tx %s\n", hashTx.ToString().c_str());
    }
    return false;
}



// Scan the block chain (starting in pindexStart) for transactions
// from or to us. If fUpdate is true, found transactions that already
// exist in the wallet will be updated.
int CWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate)
{
    int ret = 0;

    CBlockIndex* pindex = pindexStart;
    {
        LOCK(cs_wallet);
        while (pindex)
        {
            // no need to read and scan block, if block was created before
            // our wallet birthday (as adjusted for block time variability)
            if (nTimeFirstKey && (pindex->nTime < (nTimeFirstKey - 7200))) {
                pindex = pindex->pnext;
                continue;
            }

            CBlock block;
            block.ReadFromDisk(pindex, true);
            BOOST_FOREACH(CTransaction& tx, block.vtx)
            {
                if (AddToWalletIfInvolvingMe(tx, &block, fUpdate))
                    ret++;
            }
            pindex = pindex->pnext;
        }
    }
    return ret;
}

int CWallet::ScanForWalletTransaction(const uint256& hashTx)
{
    CTransaction tx;
    tx.ReadFromDisk(COutPoint(hashTx, 0));
    if (AddToWalletIfInvolvingMe(tx, NULL, true, true))
        return 1;
    return 0;
}

void CWallet::ReacceptWalletTransactions()
{
    CTxDB txdb("r");
    bool fRepeat = true;
    while (fRepeat)
    {
        LOCK(cs_wallet);
        fRepeat = false;
        vector<CDiskTxPos> vMissingTx;
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            if ((wtx.IsCoinBase() && wtx.IsSpent(0)) || (wtx.IsCoinStake() && wtx.IsSpent(1)))
                continue;

            CTxIndex txindex;
            bool fUpdated = false;
            if (txdb.ReadTxIndex(wtx.GetHash(), txindex))
            {
                // Update fSpent if a tx got spent somewhere else by a copy of wallet.dat
                if (txindex.vSpent.size() != wtx.vout.size())
                {
                    printf("ERROR: ReacceptWalletTransactions() : txindex.vSpent.size() %"PRIszu" != wtx.vout.size() %"PRIszu"\n", txindex.vSpent.size(), wtx.vout.size());
                    continue;
                }
                for (unsigned int i = 0; i < txindex.vSpent.size(); i++)
                {
                    if (wtx.IsSpent(i))
                        continue;
                    if (!txindex.vSpent[i].IsNull() && IsMine(wtx.vout[i]))
                    {
                        wtx.MarkSpent(i);
                        fUpdated = true;
                        vMissingTx.push_back(txindex.vSpent[i]);
                    }
                }
                if (fUpdated)
                {
                    printf("ReacceptWalletTransactions found spent coin %s SUM %s\n", FormatMoney(wtx.GetCredit()).c_str(), wtx.GetHash().ToString().c_str());
                    wtx.MarkDirty();
                    wtx.WriteToDisk();
                }
            }
            else
            {
                // Re-accept any txes of ours that aren't already in a block
                if (!(wtx.IsCoinBase() || wtx.IsCoinStake()))
                    wtx.AcceptWalletTransaction(txdb);
            }
        }
        if (!vMissingTx.empty())
        {
            // TODO: optimize this to scan just part of the block chain?
            if (ScanForWalletTransactions(pindexGenesisBlock))
                fRepeat = true;  // Found missing transactions: re-do re-accept.
        }
    }
}

void CWalletTx::RelayWalletTransaction(CTxDB& txdb)
{
    BOOST_FOREACH(const CMerkleTx& tx, vtxPrev)
    {
        if (!(tx.IsCoinBase() || tx.IsCoinStake()))
        {
            uint256 hash = tx.GetHash();
            if (!txdb.ContainsTx(hash))
                RelayTransaction((CTransaction)tx, hash);
        }
    }
    if (!(IsCoinBase() || IsCoinStake()))
    {
        uint256 hash = GetHash();
        if (!txdb.ContainsTx(hash))
        {
            printf("Relaying wtx %s\n", hash.ToString().substr(0,10).c_str());
            RelayTransaction((CTransaction)*this, hash);
        }
    }
}

void CWalletTx::RelayWalletTransaction()
{
   CTxDB txdb("r");
   RelayWalletTransaction(txdb);
}

void CWallet::ResendWalletTransactions(bool fForce)
{
    if (!fForce)
    {
        // Do this infrequently and randomly to avoid giving away
        // that these are our transactions.
        static int64_t nNextTime;
        if (GetTime() < nNextTime)
            return;
        bool fFirst = (nNextTime == 0);
        nNextTime = GetTime() + GetRand(30 * 60);
        if (fFirst)
            return;

        // Only do it if there's been a new block since last time
        static int64_t nLastTime;
        if (nTimeBestReceived < nLastTime)
            return;
        nLastTime = GetTime();
    }

    // Rebroadcast any of our txes that aren't in a block yet
    printf("ResendWalletTransactions()\n");
    CTxDB txdb("r");
    {
        LOCK(cs_wallet);
        // Sort them in chronological order
        multimap<unsigned int, CWalletTx*> mapSorted;
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            // Don't rebroadcast until it's had plenty of time that
            // it should have gotten in already by now.
            if (fForce || nTimeBestReceived - (int64_t)wtx.nTimeReceived > 5 * 60)
                mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
        }
        BOOST_FOREACH(PAIRTYPE(const unsigned int, CWalletTx*)& item, mapSorted)
        {
            CWalletTx& wtx = *item.second;
            if (wtx.CheckTransaction())
                wtx.RelayWalletTransaction(txdb);
            else
                printf("ResendWalletTransactions() : CheckTransaction failed for transaction %s\n", wtx.GetHash().ToString().c_str());
        }
    }
}






//////////////////////////////////////////////////////////////////////////////
//
// Actions
//


int64_t CWallet::GetBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableCredit();
        }
    }

    return nTotal;
}

int64_t CWallet::GetUnconfirmedBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal() || !pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableCredit();
        }
    }
    return nTotal;
}

int64_t CWallet::GetImmatureBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx& pcoin = (*it).second;
            if (pcoin.IsCoinBase() && pcoin.GetBlocksToMaturity() > 0 && pcoin.IsInMainChain())
                nTotal += GetCredit(pcoin);
        }
    }
    return nTotal;
}

// populate vCoins with vector of spendable COutputs
void CWallet::AvailableCoins(vector<COutput>& vCoins, bool fOnlyConfirmed, const CCoinControl *coinControl) const
{
    vCoins.clear();

    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;

            if (!pcoin->IsFinal())
                continue;

            if (fOnlyConfirmed && !pcoin->IsTrusted())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            if(pcoin->IsCoinStake() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < 0)
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++)
                if (!(pcoin->IsSpent(i)) && IsMine(pcoin->vout[i]) && pcoin->vout[i].nValue >= nMinimumInputValue &&
                (!coinControl || !coinControl->HasSelected() || coinControl->IsSelected((*it).first, i)))
                    vCoins.push_back(COutput(pcoin, i, nDepth));

        }
    }
}

void CWallet::AvailableCoinsMinConf(vector<COutput>& vCoins, int nConf) const
{
    vCoins.clear();

    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;

            if (!pcoin->IsFinal())
                continue;

            if(pcoin->GetDepthInMainChain() < nConf)
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++)
                if (!(pcoin->IsSpent(i)) && IsMine(pcoin->vout[i]) && pcoin->vout[i].nValue >= nMinimumInputValue)
                    vCoins.push_back(COutput(pcoin, i, pcoin->GetDepthInMainChain()));
        }
    }
}

static void ApproximateBestSubset(vector<pair<int64_t, pair<const CWalletTx*,unsigned int> > >vValue, int64_t nTotalLower, int64_t nTargetValue,
                                  vector<char>& vfBest, int64_t& nBest, int iterations = 1000)
{
    vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        int64_t nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                if (nPass == 0 ? rand() % 2 : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

// ppcoin: total coins staked (non-spendable until maturity)
int64_t CWallet::GetStake() const
{
    int64_t nTotal = 0;
    LOCK(cs_wallet);
    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        const CWalletTx* pcoin = &(*it).second;
        if (pcoin->IsCoinStake() && pcoin->GetBlocksToMaturity() > 0 && pcoin->GetDepthInMainChain() > 0)
            nTotal += CWallet::GetCredit(*pcoin);
    }
    return nTotal;
}

int64_t CWallet::GetNewMint() const
{
    int64_t nTotal = 0;
    LOCK(cs_wallet);
    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        const CWalletTx* pcoin = &(*it).second;
        if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0 && pcoin->GetDepthInMainChain() > 0)
            nTotal += CWallet::GetCredit(*pcoin);
    }
    return nTotal;
}

bool CWallet::SelectCoinsMinConf(int64_t nTargetValue, unsigned int nSpendTime, int nConfMine, int nConfTheirs, vector<COutput> vCoins, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    pair<int64_t, pair<const CWalletTx*,unsigned int> > coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<int64_t>::max();
    coinLowestLarger.second.first = NULL;
    vector<pair<int64_t, pair<const CWalletTx*,unsigned int> > > vValue;
    int64_t nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    BOOST_FOREACH(COutput output, vCoins)
    {
        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < (pcoin->IsFromMe() ? nConfMine : nConfTheirs))
            continue;

        int i = output.i;

        // Follow the timestamp rules
        if (pcoin->nTime > nSpendTime)
            continue;

        int64_t n = pcoin->vout[i].nValue;

        pair<int64_t,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));

        if (n == nTargetValue)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            return true;
        }
        else if (n < nTargetValue + CENT)
        {
            vValue.push_back(coin);
            nTotalLower += n;
        }
        else if (n < coinLowestLarger.first)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (unsigned int i = 0; i < vValue.size(); ++i)
        {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (coinLowestLarger.second.first == NULL)
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        return true;
    }

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
    vector<char> vfBest;
    int64_t nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest, 1000);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + CENT)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + CENT, vfBest, nBest, 1000);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first &&
        ((nBest != nTargetValue && nBest < nTargetValue + CENT) || coinLowestLarger.first <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    }
    else {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
            }

        if (fDebug && GetBoolArg("-printpriority"))
        {
            //// debug print
            printf("SelectCoins() best subset: ");
            for (unsigned int i = 0; i < vValue.size(); i++)
                if (vfBest[i])
                    printf("%s ", FormatMoney(vValue[i].first).c_str());
            printf("total %s\n", FormatMoney(nBest).c_str());
        }
    }

    return true;
}

bool CWallet::SelectCoins(int64_t nTargetValue, unsigned int nSpendTime, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet, const CCoinControl* coinControl) const
{
    vector<COutput> vCoins;
    AvailableCoins(vCoins, true, coinControl);

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected())
    {
        BOOST_FOREACH(const COutput& out, vCoins)
        {
            nValueRet += out.tx->vout[out.i].nValue;
            setCoinsRet.insert(make_pair(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }

    return (SelectCoinsMinConf(nTargetValue, nSpendTime, 1, 6, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, nSpendTime, 1, 1, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, nSpendTime, 0, 1, vCoins, setCoinsRet, nValueRet));
}

// Select some coins without random shuffle or best subset approximation
bool CWallet::SelectCoinsSimple(int64_t nTargetValue, unsigned int nSpendTime, int nMinConf, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet) const
{
    vector<COutput> vCoins;
    AvailableCoinsMinConf(vCoins, nMinConf);

    setCoinsRet.clear();
    nValueRet = 0;

    BOOST_FOREACH(COutput output, vCoins)
    {
        const CWalletTx *pcoin = output.tx;
        int i = output.i;

        // Stop if we've chosen enough inputs
        if (nValueRet >= nTargetValue)
            break;

        // Follow the timestamp rules
        if (pcoin->nTime > nSpendTime)
            continue;

        int64_t n = pcoin->vout[i].nValue;

        pair<int64_t,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));

        if (n >= nTargetValue)
        {
            // If input value is greater or equal to target then simply insert
            //    it into the current subset and exit
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            break;
        }
        else if (n < nTargetValue + CENT)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
        }
    }

    return true;
}

bool CWallet::CreateTransaction(const vector<pair<CScript, int64_t> >& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, int64_t& nFeeRet, const CCoinControl* coinControl)
{
    int64_t nValue = 0;
    BOOST_FOREACH (const PAIRTYPE(CScript, int64_t)& s, vecSend)
    {
        if (nValue < 0)
            return false;
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0)
        return false;

    wtxNew.BindWallet(this);

    {
        LOCK2(cs_main, cs_wallet);
        // txdb must be opened before the mapWallet lock
        CTxDB txdb("r");
        {
            nFeeRet = nTransactionFee;
            while (true)
            {
                wtxNew.vin.clear();
                wtxNew.vout.clear();
                wtxNew.fFromMe = true;

                int64_t nTotalValue = nValue + nFeeRet;
                double dPriority = 0;
                // vouts to the payees
                BOOST_FOREACH (const PAIRTYPE(CScript, int64_t)& s, vecSend)
                    wtxNew.vout.push_back(CTxOut(s.second, s.first));

                // Choose coins to use
                set<pair<const CWalletTx*,unsigned int> > setCoins;
                int64_t nValueIn = 0;
                if (!SelectCoins(nTotalValue, wtxNew.nTime, setCoins, nValueIn, coinControl))
                    return false;
                BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
                {
                    int64_t nCredit = pcoin.first->vout[pcoin.second].nValue;
                    dPriority += (double)nCredit * pcoin.first->GetDepthInMainChain();
                }

                int64_t nChange = nValueIn - nValue - nFeeRet;
                // if sub-cent change is required, the fee must be raised to at least MIN_TX_FEE
                // or until nChange becomes zero
                // NOTE: this depends on the exact behaviour of GetMinFee
                if (nFeeRet < MIN_TX_FEE && nChange > 0 && nChange < CENT)
                {
                    int64_t nMoveToFee = min(nChange, MIN_TX_FEE - nFeeRet);
                    nChange -= nMoveToFee;
                    nFeeRet += nMoveToFee;
                }

                if (nChange > 0)
                {
                    // Fill a vout to ourself
                    // TODO: pass in scriptChange instead of reservekey so
                    // change transaction isn't always pay-to-bitcoin-address
                    CScript scriptChange;

                    // coin control: send change to custom address
                    if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange)) {
                        scriptChange.SetDestination(coinControl->destChange);
                        if (fDebug) printf("coin control: send change to custom address\n script change: %s\n",
                                           scriptChange.ToString(false).c_str());
                   }
                    // no coin control: send change to newly generated address
                    else
                    {
                        // Note: We use a new key here to keep it from being obvious which side is the change.
                        //  The drawback is that by not reusing a previous key, the change may be lost if a
                        //  backup is restored, if the backup doesn't have the new private key for the change.
                        //  If we reused the old key, it would be possible to add code to look for and
                        //  rediscover unknown transactions that were written with keys of ours to recover
                        //  post-backup change.

                        // Reserve a new key pair from key pool
                        CPubKey vchPubKey; //= reservekey.GetReservedKey();
                        reservekey.GetReservedKeyIn(vchPubKey);

                        scriptChange.SetDestination(vchPubKey.GetID());
                        if (fDebug) printf("no coin control: send change to new address\n script change: %s \n",
                                           scriptChange.ToString(false).c_str());
                    }

                    // Insert change txn at random position:
                    vector<CTxOut>::iterator position = wtxNew.vout.begin()+GetRandInt(wtxNew.vout.size());
                    wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
                }
                else
                    reservekey.ReturnKey();

                // Fill vin
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                    wtxNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second));

                // Sign
                int nIn = 0;
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                    if (!SignSignature(*this, *coin.first, wtxNew, nIn++))
                        return false;

                // Limit size
                unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION);
                if (nBytes >= MAX_BLOCK_SIZE_GEN/5)
                    return false;
                dPriority /= nBytes;

                // Check that enough fee is included
                int64_t nPayFee = nTransactionFee * (1 + (int64_t)nBytes / 1000);
                int64_t nMinFee = wtxNew.GetMinFee(1, GMF_SEND, nBytes);

                if (nFeeRet < max(nPayFee, nMinFee))
                {
                    nFeeRet = max(nPayFee, nMinFee);
                    continue;
                }

                // Fill vtxPrev by copying from previous transactions vtxPrev
                wtxNew.AddSupportingTransactions(txdb);
                wtxNew.fTimeReceivedIsTxTime = true;

                break;
            }
        }
    }
    return true;
}

bool CWallet::CreateTransaction(CScript scriptPubKey, int64_t nValue, CWalletTx& wtxNew, CReserveKey& reservekey, int64_t& nFeeRet, const CCoinControl* coinControl)
{
    vector< pair<CScript, int64_t> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));
    return CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet, coinControl);
}

// get current stake weight
bool CWallet::GetStakeWeight(const CKeyStore& keystore, uint64_t& nMinWeight, uint64_t& nMaxWeight, uint64_t& nWeight)
{
    // Choose coins to use
    int64_t nBalance = GetBalance();

    if (nBalance <= nReserveBalance)
        return false;

    vector<const CWalletTx*> vwtxPrev;

    set<pair<const CWalletTx*,unsigned int> > setCoins;
    int64_t nValueIn = 0;

    if (!SelectCoinsSimple(nBalance - nReserveBalance, GetTime(), nCoinbaseMaturity + 10, setCoins, nValueIn))
        return false;

    if (setCoins.empty())
        return false;

    CTxDB txdb("r");
    BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
    {
        CTxIndex txindex;
        {
            LOCK2(cs_main, cs_wallet);
            if (!txdb.ReadTxIndex(pcoin.first->GetHash(), txindex))
                continue;
        }

        int64_t nTimeWeight = GetWeight((int64_t)pcoin.first->nTime, (int64_t)GetTime());
        CBigNum bnCoinDayWeight = CBigNum(pcoin.first->vout[pcoin.second].nValue) * nTimeWeight / COIN / (24 * 60 * 60);

        // Weight is greater than zero
        if (nTimeWeight > 0)
        {
            nWeight += bnCoinDayWeight.getuint64();
        }

        // Weight is greater than zero, but the maximum value isn't reached yet
        if (nTimeWeight > 0 && nTimeWeight < nStakeMaxAge)
        {
            nMinWeight += bnCoinDayWeight.getuint64();
        }

        // Maximum weight was reached
        if (nTimeWeight == nStakeMaxAge)
        {
            nMaxWeight += bnCoinDayWeight.getuint64();
        }
    }

    return true;
}

bool CWallet::CreateCoinStake(const CKeyStore& keystore, unsigned int nBits, int64_t nSearchInterval, int64_t nFees, CTransaction& txNew, CKey& key)
{
    CBlockIndex* pindexPrev = pindexBest;
    CBigNum bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);

    txNew.vin.clear();
    txNew.vout.clear();

    // Mark coin stake transaction
    CScript scriptEmpty;
    scriptEmpty.clear();
    txNew.vout.push_back(CTxOut(0, scriptEmpty));

    // Choose coins to use
    int64_t nBalance = GetBalance();

    if (nBalance <= nReserveBalance)
        return false;

    vector<const CWalletTx*> vwtxPrev;

    set<pair<const CWalletTx*,unsigned int> > setCoins;
    int64_t nValueIn = 0;

    // Select coins with suitable depth
    if (!SelectCoinsSimple(nBalance - nReserveBalance, txNew.nTime, nCoinbaseMaturity + 10, setCoins, nValueIn))
        return false;

    if (setCoins.empty())
        return false;

    int64_t nCredit = 0;
    CScript scriptPubKeyKernel;
    CTxDB txdb("r");
    BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
    {
        CTxIndex txindex;
        {
            LOCK2(cs_main, cs_wallet);
            if (!txdb.ReadTxIndex(pcoin.first->GetHash(), txindex))
                continue;
        }

        // Read block header
        CBlock block;
        {
            LOCK2(cs_main, cs_wallet);
            if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
                continue;
        }

        static int nMaxStakeSearchInterval = 60;
        if (block.GetBlockTime() + nStakeMinAge > txNew.nTime - nMaxStakeSearchInterval)
            continue; // only count coins meeting min age requirement

        bool fKernelFound = false;
        for (unsigned int n=0; n<min(nSearchInterval,(int64_t)nMaxStakeSearchInterval) && !fKernelFound && !fShutdown && pindexPrev == pindexBest; n++)
        {
            // Search backward in time from the given txNew timestamp
            // Search nSearchInterval seconds back up to nMaxStakeSearchInterval
            uint256 hashProofOfStake = 0, targetProofOfStake = 0;
            COutPoint prevoutStake = COutPoint(pcoin.first->GetHash(), pcoin.second);
            if (CheckStakeKernelHash(nBits, block, txindex.pos.nTxPos - txindex.pos.nBlockPos, *pcoin.first, prevoutStake, txNew.nTime - n, hashProofOfStake, targetProofOfStake))
            {
                // Found a kernel
                if (fDebug && GetBoolArg("-printcoinstake"))
                    printf("CreateCoinStake : kernel found\n");
                vector<valtype> vSolutions;
                txnouttype whichType;
                CScript scriptPubKeyOut;
                scriptPubKeyKernel = pcoin.first->vout[pcoin.second].scriptPubKey;
                if (!Solver(scriptPubKeyKernel, whichType, vSolutions))
                {
                    if (fDebug && GetBoolArg("-printcoinstake"))
                        printf("CreateCoinStake : failed to parse kernel\n");
                    break;
                }
                if (fDebug && GetBoolArg("-printcoinstake"))
                    printf("CreateCoinStake : parsed kernel type=%d\n", whichType);
                if (whichType != TX_PUBKEY && whichType != TX_PUBKEYHASH)
                {
                    if (fDebug && GetBoolArg("-printcoinstake"))
                        printf("CreateCoinStake : no support for kernel type=%d\n", whichType);
                    break;  // only support pay to public key and pay to address
                }
                if (whichType == TX_PUBKEYHASH) // pay to address type
                {
                    // convert to pay to public key type
                    if (!keystore.GetKey(uint160(vSolutions[0]), key))
                    {
                        if (fDebug && GetBoolArg("-printcoinstake"))
                            printf("CreateCoinStake : failed to get key for kernel type=%d\n", whichType);
                        break;  // unable to find corresponding public key
                    }
                    scriptPubKeyOut << key.GetPubKey() << OP_CHECKSIG;
                }
                if (whichType == TX_PUBKEY)
                {
                    valtype& vchPubKey = vSolutions[0];
                    if (!keystore.GetKey(Hash160(vchPubKey), key))
                    {
                        if (fDebug && GetBoolArg("-printcoinstake"))
                            printf("CreateCoinStake : failed to get key for kernel type=%d\n", whichType);
                        break;  // unable to find corresponding public key
                    }

                if (key.GetPubKey() != vchPubKey)
                {
                    if (fDebug && GetBoolArg("-printcoinstake"))
                        printf("CreateCoinStake : invalid key for kernel type=%d\n", whichType);
                        break; // keys mismatch
                    }

                    scriptPubKeyOut = scriptPubKeyKernel;
                }

                txNew.nTime -= n;
                txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
                nCredit += pcoin.first->vout[pcoin.second].nValue;
                vwtxPrev.push_back(pcoin.first);
                txNew.vout.push_back(CTxOut(0, scriptPubKeyOut));

                if (GetWeight(block.GetBlockTime(), (int64_t)txNew.nTime) < nStakeSplitAge)
                    txNew.vout.push_back(CTxOut(0, scriptPubKeyOut)); //split stake
                if (fDebug && GetBoolArg("-printcoinstake"))
                    printf("CreateCoinStake : added kernel type=%d\n", whichType);
                fKernelFound = true;
                break;
            }
        }

        if (fKernelFound || fShutdown)
            break; // if kernel is found stop searching
    }

    if (nCredit == 0 || nCredit > nBalance - nReserveBalance)
        return false;

    BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
    {
        // Attempt to add more inputs
        // Only add coins of the same key/address as kernel
        if (txNew.vout.size() == 2 && ((pcoin.first->vout[pcoin.second].scriptPubKey == scriptPubKeyKernel || pcoin.first->vout[pcoin.second].scriptPubKey == txNew.vout[1].scriptPubKey))
            && pcoin.first->GetHash() != txNew.vin[0].prevout.hash)
        {
            int64_t nTimeWeight = GetWeight((int64_t)pcoin.first->nTime, (int64_t)txNew.nTime);

            // Stop adding more inputs if already too many inputs
            if (txNew.vin.size() >= 100)
                break;
            // Stop adding more inputs if value is already pretty significant
            if (nCredit >= nStakeCombineThreshold)
                break;
            // Stop adding inputs if reached reserve limit
            if (nCredit + pcoin.first->vout[pcoin.second].nValue > nBalance - nReserveBalance)
                break;
            // Do not add additional significant input
            if (pcoin.first->vout[pcoin.second].nValue >= nStakeCombineThreshold)
                continue;
            // Do not add input that is still too young
            if (nTimeWeight < nStakeMinAge)
                continue;

            txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
            nCredit += pcoin.first->vout[pcoin.second].nValue;
            vwtxPrev.push_back(pcoin.first);
        }
    }

    // Calculate coin age reward
    {
        uint64_t nCoinAge;
        CTxDB txdb("r");
        if (!txNew.GetCoinAge(txdb, nCoinAge))
            return error("CreateCoinStake : failed to calculate coin age");

        int64_t nReward = GetProofOfStakeReward(nCoinAge, nFees);
        if (nReward <= 0)
            return false;

        nCredit += nReward;
    }

    // Set output amount
    if (txNew.vout.size() == 3)
    {
        txNew.vout[1].nValue = (nCredit / 2 / CENT) * CENT;
        txNew.vout[2].nValue = nCredit - txNew.vout[1].nValue;
    }
    else
        txNew.vout[1].nValue = nCredit;

    // Sign
    int nIn = 0;
    BOOST_FOREACH(const CWalletTx* pcoin, vwtxPrev)
    {
        if (!SignSignature(*this, *pcoin, txNew, nIn++))
            return error("CreateCoinStake : failed to sign coinstake");
    }

    // Limit size
    unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);
    if (nBytes >= MAX_BLOCK_SIZE_GEN/5)
        return error("CreateCoinStake : exceeded coinstake size limit");

    // Successfully generated coinstake
    return true;
}


// Call after CreateTransaction unless you want to abort
bool CWallet::CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey)
{
    {
        LOCK2(cs_main, cs_wallet);
        printf("CommitTransaction:\n%s", wtxNew.ToString().c_str());
        {
            // This is only to keep the database open to defeat the auto-flush for the
            // duration of this scope.  This is the only place where this optimization
            // maybe makes sense; please don't do it anywhere else.
            CWalletDB* pwalletdb = fFileBacked ? new CWalletDB(strWalletFile,"r") : NULL;

            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew);

            // Mark old coins as spent
            set<CWalletTx*> setCoins;
            BOOST_FOREACH(const CTxIn& txin, wtxNew.vin)
            {
                CWalletTx &coin = mapWallet[txin.prevout.hash];
                coin.BindWallet(this);
                coin.MarkSpent(txin.prevout.n);
                coin.WriteToDisk();
                NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
            }

            if (fFileBacked)
                delete pwalletdb;
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.GetHash()] = 0;

        // Broadcast
        if (!wtxNew.AcceptToMemoryPool())
        {
            // This must not fail. The transaction has already been signed and recorded.
            printf("CommitTransaction() : Error: Transaction not valid\n");
            return false;
        }
        wtxNew.RelayWalletTransaction();
    }
    return true;
}




string CWallet::SendMoney(CScript scriptPubKey, int64_t nValue, CWalletTx& wtxNew, bool fAskFee)
{
    CReserveKey reservekey(this);
    int64_t nFeeRequired;

    if (IsLocked())
    {
        string strError = _("Error: Wallet locked, unable to create transaction  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }
    if (fWalletUnlockStakingOnly)
    {
        string strError = _("Error: Wallet unlocked for staking only, unable to create transaction.");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }
    if (!CreateTransaction(scriptPubKey, nValue, wtxNew, reservekey, nFeeRequired))
    {
        string strError;
        if (nValue + nFeeRequired > GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds  "), FormatMoney(nFeeRequired).c_str());
        else
            strError = _("Error: Transaction creation failed  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired, _("Sending...")))
        return "ABORTED";

    if (!CommitTransaction(wtxNew, reservekey))
        return _("Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

    return "";
}



string CWallet::SendMoneyToDestination(const CTxDestination& address, int64_t nValue, CWalletTx& wtxNew, bool fAskFee)
{
    // Check amount
    if (nValue <= 0)
        return _("Invalid amount");
    if (nValue + nTransactionFee > GetBalance())
        return _("Insufficient funds");

    // Parse Bitcoin address
    CScript scriptPubKey;
    scriptPubKey.SetDestination(address);

    return SendMoney(scriptPubKey, nValue, wtxNew, fAskFee);
}




DBErrors CWallet::LoadWallet(bool& fFirstRunRet)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    fFirstRunRet = false;
    DBErrors nLoadWalletRet = CWalletDB(strWalletFile,"cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // the requires a new key.
        }
    }

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;
    fFirstRunRet = !vchDefaultKey.IsValid();

    NewThread(ThreadFlushWalletDB, &strWalletFile);
    return DB_LOAD_OK;
}


bool CWallet::SetAddressBookName(const CTxDestination& address, const string& strName)
{
    std::map<CTxDestination, std::string>::iterator mi = mapAddressBook.find(address);
    mapAddressBook[address] = strName;
    NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address), (mi == mapAddressBook.end()) ? CT_NEW : CT_UPDATED);
    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).WriteName(CBitcoinAddress(address).ToString(), strName);
}

bool CWallet::DelAddressBookName(const CTxDestination& address)
{
    mapAddressBook.erase(address);
    NotifyAddressBookChanged(this, address, "", ::IsMine(*this, address), CT_DELETED);
    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).EraseName(CBitcoinAddress(address).ToString());
}



void CWallet::PrintWallet(const CBlock& block)
{
    {
        LOCK(cs_wallet);
        if (block.IsProofOfWork() && mapWallet.count(block.vtx[0].GetHash()))
        {
            CWalletTx& wtx = mapWallet[block.vtx[0].GetHash()];
            printf("    mine:  %d  %d  %"PRId64"", wtx.GetDepthInMainChain(), wtx.GetBlocksToMaturity(), wtx.GetCredit());
        }
        if (block.IsProofOfStake() && mapWallet.count(block.vtx[1].GetHash()))
        {
            CWalletTx& wtx = mapWallet[block.vtx[1].GetHash()];
            printf("    stake: %d  %d  %"PRId64"", wtx.GetDepthInMainChain(), wtx.GetBlocksToMaturity(), wtx.GetCredit());
         }

    }
    printf("\n");
}

bool CWallet::GetTransaction(const uint256 hashTx, CWalletTx& wtx)
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
        {
            wtx = (*mi).second;
            return true;
        }
    }
    return false;
}

bool CWallet::SetDefaultKey(const CPubKey &vchPubKey)
{
    if (fFileBacked)
    {
        if (!CWalletDB(strWalletFile).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

bool GetWalletFile(CWallet* pwallet, string &strWalletFileOut)
{
    if (!pwallet->fFileBacked)
        return false;
    strWalletFileOut = pwallet->strWalletFile;
    return true;
}

//
// Mark old keypool keys as used,
// and generate all new keys
//
bool CWallet::NewKeyPool()
{
    {
        LOCK(cs_wallet);
        CWalletDB walletdb(strWalletFile);
        BOOST_FOREACH(int64_t nIndex, setKeyPool)
            walletdb.ErasePool(nIndex);
        setKeyPool.clear();

        if (IsLocked())
            return false;

        int64_t nKeys = max(GetArg("-keypool", 100), (int64_t)0);
        for (int i = 0; i < nKeys; i++)
        {
            int64_t nIndex = i+1;
            walletdb.WritePool(nIndex, CKeyPool(GenerateNewKey()));
            setKeyPool.insert(nIndex);
        }
        printf("CWallet::NewKeyPool wrote %"PRId64" new keys\n", nKeys);
    }
    return true;
}

bool CWallet::TopUpKeyPool(unsigned int nSize)
{
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        CWalletDB walletdb(strWalletFile);

        // Top up key pool
        unsigned int nTargetSize;
        if (nSize > 0)
            nTargetSize = nSize;
        else
            nTargetSize = max(GetArg("-keypool", 100), (int64_t)0);

        while (setKeyPool.size() < (nTargetSize + 1))
        {
            int64_t nEnd = 1;
            if (!setKeyPool.empty())
                nEnd = *(--setKeyPool.end()) + 1;
            if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey())))
                throw runtime_error("TopUpKeyPool() : writing generated key failed");
            setKeyPool.insert(nEnd);
            printf("keypool added key %"PRId64", size=%"PRIszu"\n", nEnd, setKeyPool.size());
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        // Get the oldest key
        if(setKeyPool.empty())
            return;

        CWalletDB walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw runtime_error("ReserveKeyFromKeyPool() : read failed");
        if (!HaveKey(keypool.vchPubKey.GetID()))
            throw runtime_error("ReserveKeyFromKeyPool() : unknown key in key pool");
        assert(keypool.vchPubKey.IsValid());
        if (fDebug && GetBoolArg("-printkeypool"))
            printf("keypool reserve %"PRId64"\n", nIndex);
    }
}

int64_t CWallet::AddReserveKey(const CKeyPool& keypool)
{
    {
        LOCK2(cs_main, cs_wallet);
        CWalletDB walletdb(strWalletFile);

        int64_t nIndex = 1 + *(--setKeyPool.end());
        if (!walletdb.WritePool(nIndex, keypool))
            throw runtime_error("AddReserveKey() : writing added key failed");
        setKeyPool.insert(nIndex);
        return nIndex;
    }
    return -1;
}

void CWallet::KeepKey(int64_t nIndex)
{
    // Remove from key pool
    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    if(fDebug)
        printf("keypool keep %"PRId64"\n", nIndex);
}

void CWallet::ReturnKey(int64_t nIndex)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    if(fDebug)
        printf("keypool return %"PRId64"\n", nIndex);
}

bool SendByDelegate(
    CWallet* wallet,
    CBitcoinAddress const& recipient_address,
    int64_t const& nAmount,
    CAddress& sufficient
) {

    CScript address_script;

    address_script.SetDestination(recipient_address.Get());

    std::map<CAddress, uint64_t> advertised_balances = ListAdvertisedBalances();

    bool found = false;

    //find delegate candidate
    for (
        std::map<
            CAddress,
            uint64_t
        >::const_iterator address = advertised_balances.begin();
        advertised_balances.end() != address;
        address++
    ) {
        if (nAmount <= (int64_t)address->second) {
            found = true;
            sufficient = address->first;
            break;
        }
    }

    if (!found) {
        return false;
    }

    CNetAddr const local = GetLocalTorAddress(sufficient);
    //put addr into vector
    vector<unsigned char> identification(16);
    for (
        int filling = 0;
        16 > filling;
        filling++
    ) {
        identification[filling] = local.GetByte(15 - filling);
    }

    uint64_t const join_nonce = GetRand(std::numeric_limits<uint64_t>::max());

    std::vector<unsigned char> const key = DelegateManager::store( false,
                                                                   local,
                                                                   sufficient,
                                                                   address_script,
                                                                   nAmount
                                                                   );

    wallet->store_join_nonce_delegate(join_nonce, key);

    CTransaction rawTx;

    CTxOut transfer;
    transfer.scriptPubKey = CScript() << join_nonce << identification << key;
    transfer.scriptPubKey += address_script;
    transfer.nValue = nAmount;

    rawTx.vout.push_back(transfer);
    try {
        PushOffChain(sufficient, "request-delegate", rawTx);
    }   catch (std::exception& e) {
            PrintExceptionContinue(&e, "SendByDelegate()");
            return false;
    }
    return true;
}

void SignBind(
    CWallet* wallet,
    CTransaction& mergedTx,
    CBitcoinAddress const& address,
    bool const& isDelegate
) {
    for (
        vector<CTxOut>::iterator output = mergedTx.vout.begin();
        mergedTx.vout.end() != output;
        output++
    ) {
        int at_data = 0;
        CScript with_signature;
        opcodetype opcode;
        std::vector<unsigned char> vch;
        CScript::const_iterator pc = output->scriptPubKey.begin();
        while (pc < output->scriptPubKey.end())
        {
            if (!output->scriptPubKey.GetOp(pc, opcode, vch))
            {
                throw runtime_error("error parsing script");
            }
            if (0 <= opcode && opcode <= OP_PUSHDATA4) {
                with_signature << vch;
                if ((!isDelegate && at_data == 1) || (isDelegate && at_data == 2 )) {

                    with_signature << OP_DUP;
                    uint256 hash = Hash(vch.begin(), vch.end());

                    if (!Sign1(boost::get<CKeyID>(address.Get()), *wallet, hash, SIGHASH_ALL, with_signature)) {
                        throw runtime_error("data signing failed");
                    }

                    CPubKey public_key;
                    wallet->GetPubKey(boost::get<CKeyID>(address.Get()), public_key);
                    with_signature << public_key;
                    with_signature << OP_CHECKDATASIG << OP_VERIFY;
                    with_signature << OP_SWAP << OP_HASH160 << OP_EQUAL;
                    with_signature << OP_VERIFY;
                    if ((!isDelegate && at_data == 1) || (isDelegate && at_data == 2 )) at_data = 0;
                }
            }
            else {
                with_signature << opcode;
                if (OP_IF == opcode) {
                    at_data++;
                } else {
                    at_data = 0;
                }
            }
        }
        output->scriptPubKey = with_signature;
    }
}

bool CWallet::push_off_chain_transaction(
    std::string const& name,
    CTransaction const& tx
) {
    LOCK(cs_wallet);
    if (GetBoolArg("-processoffchain", true)) {
        if (ProcessOffChain(this, name, tx, GetTime() + 6000)) {
            return true;
        }
    }
    off_chain_transactions.push_back(std::make_pair(name, tx));
    return true;
}

bool CWallet::pop_off_chain_transaction(std::string& name, CTransaction& tx) {
    LOCK(cs_wallet);
    if (off_chain_transactions.empty()) {
        return false;
    }
    name = off_chain_transactions.front().first;
    tx = off_chain_transactions.front().second;
    off_chain_transactions.pop_front();
    return true;
}

void CWallet::push_deferred_off_chain_transaction(
    int64_t timeout,
    std::string const& name,
    CTransaction const& tx
) {
    LOCK(cs_wallet);
    deferred_off_chain_transactions.push_back(
        std::make_pair(timeout, std::make_pair(name, tx))
    );
}

void CWallet::reprocess_deferred_off_chain_transactions() {
    LOCK(cs_wallet);
    std::list<
        std::pair<int64_t, std::pair<std::string, CTransaction> >
    > work_copy;
    work_copy.swap(
        deferred_off_chain_transactions
    );
    int64_t const now = GetTime();
    for (
        std::list<
            std::pair<int64_t, std::pair<std::string, CTransaction> >
        >::const_iterator processing = work_copy.begin();
        work_copy.end() != processing;
        processing++
    ) {
        if (now >= processing->first) {
            off_chain_transactions.push_back(
                std::make_pair(
                    processing->second.first,
                    processing->second.second
                )
            );
        } else if (
            !ProcessOffChain(
                this,
                processing->second.first,
                processing->second.second,
                processing->first
            )
        ) {
            off_chain_transactions.push_back(
                std::make_pair(
                    processing->second.first,
                    processing->second.second
                )
            );
        }
    }
}

bool CWallet::get_delegate_join_nonce(
    std::vector<unsigned char> const& key,
    uint64_t& join_nonce
) {
    for (
        std::map<
            uint64_t,
            std::vector<unsigned char>
        >::const_iterator checking = join_nonce_delegates.begin();
        join_nonce_delegates.end() != checking;
        checking++
    ) {
        if (key == checking->second) {
            join_nonce = checking->first;
            return true;
        }
    }
    return false;
}

bool CWallet::get_join_nonce_delegate(
    uint64_t const& join_nonce,
    std::vector<unsigned char>& key
) {
    if (join_nonce_delegates.end() == join_nonce_delegates.find(join_nonce)) {
        return false;
    }
    key = join_nonce_delegates.at(join_nonce);
    return true;
}


void CWallet::store_join_nonce_delegate(
    uint64_t const& join_nonce,
    std::vector<unsigned char> const& key
) {
    join_nonce_delegates[join_nonce] = key;
}


void CWallet::store_delegate_nonce(
    uint64_t const& nonce,
    std::vector<unsigned char> const& key
) {
    delegate_nonces[key] = nonce;
}

void CWallet::set_sender_bind(
    std::vector<unsigned char> const& key,
    uint256 const& bind_tx
) {
    sender_binds[key] = bind_tx;
}

bool CWallet::get_sender_bind(
    std::vector<unsigned char> const& key,
    uint256& bind_tx
) {
    if (sender_binds.end() == sender_binds.find(key)) {
        return false;
    }
    bind_tx = sender_binds.at(key);
    return true;
}

CTransaction CreateTransferFinalize(
    CWallet* wallet,
    uint256 const& funded_tx_id,
    CScript const& destination
) {
    //sender pays the delegate, this is analogous to delegates CreateTransferCommit below
    CTransaction funded_tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(funded_tx_id, funded_tx, hashBlock)) {
        throw runtime_error("transaction unknown");
    }
    int output_index = 0;

    list<
        pair<
            pair<int, CTxOut const*>, //output index, txOut
            pair<vector<unsigned char>, int> //keyhash, txtype
            >
    > foundTxOutdata;
    uint64_t value = 0;

    //get outputs from the funded tx
    for (
        vector<CTxOut>::const_iterator vout_iterator = funded_tx.vout.begin();
        funded_tx.vout.end() != vout_iterator;
        vout_iterator++,
        output_index++
    ) {
        txnouttype transaction_type;
        vector<vector<unsigned char> > values;
        if (!Solver(vout_iterator->scriptPubKey, transaction_type, values)) {
            throw std::runtime_error(
                "Unknown script " + vout_iterator->scriptPubKey.ToString()
            );
        }
        if (TX_ESCROW_SENDER == transaction_type) {
            foundTxOutdata.push_back(
                make_pair(
                    make_pair(output_index, &(*vout_iterator)),
                    make_pair(values[4], transaction_type)
                )
            );
            value += vout_iterator->nValue;
        }
        if (TX_ESCROW_FEE == transaction_type) {
            foundTxOutdata.push_back(
                make_pair(
                    make_pair(output_index, &(*vout_iterator)),
                    make_pair(values[1], transaction_type)
                )
            );
            value += vout_iterator->nValue;
        }
    }
    if (foundTxOutdata.empty()) {
        throw std::runtime_error("invalid bind transaction");
    }

    CTransaction rawTx;

    CTxOut payment_tx_out;

    payment_tx_out.scriptPubKey = destination;
    payment_tx_out.nValue = value;

    rawTx.vout.push_back(payment_tx_out);

    list<pair<CTxIn*, int> > inputs;

    rawTx.vin.resize(foundTxOutdata.size());

    int input_index = 0;

    //put outpoints in
    for (
        list<
            pair<pair<int, CTxOut const*>, pair<vector<unsigned char>, int> >
        >::const_iterator txOutData_iterator = foundTxOutdata.begin();
        foundTxOutdata.end() != txOutData_iterator;
        txOutData_iterator++,
        input_index++
    ) {
        CTxIn& input = rawTx.vin[input_index];
        input.prevout = COutPoint(funded_tx_id, txOutData_iterator->first.first);
        inputs.push_back(make_pair(&input, input_index));
    }

     //put sigs in

    list<pair<CTxIn*, int> >::const_iterator input = inputs.begin();

    for (
        list<
            pair<pair<int, CTxOut const*>, pair<vector<unsigned char>, int> >
        >::const_iterator txOutData_iterator = foundTxOutdata.begin();
        foundTxOutdata.end() != txOutData_iterator;
        txOutData_iterator++,
        input++
    ) {
        uint256 const script_hash = SignatureHash(
            txOutData_iterator->first.second->scriptPubKey,
            rawTx,
            input->second, //vin[n]
            SIGHASH_ALL
        );

        CKeyID const keyID = uint160(txOutData_iterator->second.first);
        if (
            !Sign1(
                keyID,
                *wallet,
                script_hash,
                SIGHASH_ALL,
                input->first->scriptSig
            )
        ) {
            throw std::runtime_error("signing failed");
        }

        //put pubkey in
        CPubKey public_key;
        wallet->GetPubKey(keyID, public_key);
        input->first->scriptSig << public_key;

        if (TX_ESCROW_SENDER == txOutData_iterator->second.second) {
            input->first->scriptSig << OP_FALSE;
            input->first->scriptSig = (
                CScript() << OP_FALSE
            ) + input->first->scriptSig;
        }

        input->first->scriptSig << OP_TRUE;
    }

    //verify
    input = inputs.begin();

    for (
        list<
            pair<pair<int, CTxOut const*>, pair<vector<unsigned char>, int> >
        >::const_iterator txOutData_iterator = foundTxOutdata.begin();
        foundTxOutdata.end() != txOutData_iterator;
        txOutData_iterator++,
        input++
    ) {
        if (
            !VerifyScript(
                input->first->scriptSig,
                txOutData_iterator->first.second->scriptPubKey,
                rawTx,
                input->second,
                //SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC,
                0
            )
        ) {
            throw std::runtime_error("verification failed");
        }
    }

    return rawTx;
}

CTransaction CreateTransferCommit(
    CWallet* wallet,
    uint256 const& tx_id,
    CNetAddr const& local_tor_address_parsed,
    boost::uint64_t const& delegate_address_bind_nonce,
    boost::uint64_t const& transfer_nonce,
    CScript const& destination
) {
    //delegate prepares commit tx in which he transfers the amount to the recipient

    vector<unsigned char> identification = CreateAddressIdentification(
        local_tor_address_parsed,
        delegate_address_bind_nonce
    );

    CTransaction escrowTx;
    uint256 hashBlock = 0;
    if (!GetTransaction(tx_id, escrowTx, hashBlock)) {
        throw runtime_error("transaction unknown");
    }

    //get the output of escrow
    int output_index = 0;
    CTxOut const* escrowTxOut = NULL;
    vector<unsigned char> keyhash;
    for (
        vector<CTxOut>::const_iterator vout_iterator = escrowTx.vout.begin();
        escrowTx.vout.end() != vout_iterator;
        vout_iterator++,
        output_index++
    ) {
        txnouttype transaction_type;
        vector<vector<unsigned char> > values;
        if (!Solver(vout_iterator->scriptPubKey, transaction_type, values)) {
            throw std::runtime_error(
                "Unknown script " + vout_iterator->scriptPubKey.ToString()
            );
        }
        if (TX_ESCROW == transaction_type) {
            escrowTxOut = &(*vout_iterator);
            keyhash = values[4];
            break;
        }
    }
    if (NULL == escrowTxOut) {
        throw std::runtime_error("invalid bind transaction");
    }


    CTransaction rawTx;

    //make output
    CTxOut commitTxOut;

    commitTxOut.scriptPubKey = (
        CScript() << transfer_nonce << OP_TOALTSTACK
    ) + destination;
    commitTxOut.nValue = escrowTxOut->nValue;

    rawTx.vout.push_back(commitTxOut);

    //put outpoint in
    rawTx.vin.push_back(CTxIn());

    CTxIn& input = rawTx.vin[0];

    input.prevout = COutPoint(tx_id, output_index);

    //put sig in
    uint256 const script_hash = SignatureHash(
        escrowTxOut->scriptPubKey,
        rawTx,
        0,
        SIGHASH_ALL
    );

    CKeyID const keyID = uint160(keyhash);
    if (!Sign1(keyID, *wallet, script_hash, SIGHASH_ALL, input.scriptSig)) {
        throw std::runtime_error("signing failed");
    }

    //put pubkey in
    CPubKey public_key;
    wallet->GetPubKey(keyID, public_key);
    input.scriptSig << public_key;

    input.scriptSig << identification;

    input.scriptSig << OP_TRUE;

    if (
        !VerifyScript(
            input.scriptSig,
            escrowTxOut->scriptPubKey,
            rawTx,
            0,
            //SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC,
            0
        )
    ) {
        throw std::runtime_error("verification failed");
    }

    return rawTx;
}


CTransaction CreateBind(
    CNetAddr const& local_tor_address_parsed,
    boost::uint64_t const& address_bind_nonce,
    uint64_t const& amount,
    uint64_t const& delegate_fee,
    boost::uint64_t const& expiry,
    CBitcoinAddress const& recover_address_parsed,
    bool const& is_delegate
) {
    vector<unsigned char> identification = CreateAddressIdentification(
        local_tor_address_parsed,
        address_bind_nonce
    );

    if (fDebug)
        printf("CreateBind : \n recover address : %s expiry: %"PRIu64" tor address: %s nonce: %"PRIu64"\n",
               recover_address_parsed.ToString().c_str(), expiry, local_tor_address_parsed.ToStringIP().c_str(), address_bind_nonce);

    CTransaction rawTx;
    CScript data;
    if (is_delegate) {
        data << OP_IF << Hash160(identification);
        data << boost::get<CKeyID>(recover_address_parsed.Get());
        data << OP_TOALTSTACK;
        data << OP_DUP << OP_HASH160;
        data << boost::get<CKeyID>(recover_address_parsed.Get());
        data << OP_EQUALVERIFY << OP_CHECKSIG << OP_ELSE << expiry;
        data << OP_CHECKEXPIRY;
        data << OP_ENDIF;

        rawTx.vout.push_back(CTxOut(amount, data));
    } else {
        data << OP_IF << OP_IF << Hash160(identification) << OP_CHECKTRANSFERNONCE;
        data << OP_ELSE;
        data << boost::get<CKeyID>(recover_address_parsed.Get());
        data << OP_TOALTSTACK;
        data << OP_DUP << OP_HASH160;
        data << boost::get<CKeyID>(recover_address_parsed.Get());
        data << OP_EQUALVERIFY << OP_CHECKSIG << OP_ENDIF << OP_ELSE;
        data << expiry << OP_CHECKEXPIRY;
        data << OP_ENDIF;

        rawTx.vout.push_back(CTxOut(amount, data));

        data = CScript();
        data << OP_IF;
        data << boost::get<CKeyID>(recover_address_parsed.Get());
        data << OP_TOALTSTACK;
        data << OP_DUP << OP_HASH160;
        data << boost::get<CKeyID>(recover_address_parsed.Get());
        data << OP_EQUALVERIFY << OP_CHECKSIG << OP_ELSE << expiry;
        data << OP_CHECKEXPIRY;
        data << OP_ENDIF;

        rawTx.vout.push_back(CTxOut(delegate_fee, data));
    }
    return rawTx;
}

bool GetPubKeyHash(CKeyID& key, CTxOut const& txout, txnouttype target_type) {
    CScript const payload = txout.scriptPubKey;
    txnouttype script_type;
    std::vector<std::vector<unsigned char> > data;
    if (!Solver(payload, script_type, data)) {
        return false;
    }
    if (script_type != target_type) {
        return false;
    }
    key = CPubKey(data[2]).GetID();
    return true;
}

bool GetPubKeyHash(CKeyID& key, CTransaction const& tx, bool isDelegate) {
    for (
        std::vector<CTxOut>::const_iterator txout = tx.vout.begin();
        tx.vout.end() != txout;
        txout++
    ) {
        if (GetPubKeyHash(key, *txout, isDelegate? TX_ESCROW_SENDER : TX_ESCROW )) {
            return true;
        }
    }
    return false;
}



bool CWallet::GetBoundNonce(CNetAddr const& address, uint64_t& nonce)
{
    std::set<
        std::pair<CNetAddr, uint64_t>
    > const& address_binds = get_address_binds();
    for (
        std::set<
            std::pair<CNetAddr, uint64_t>
        >::const_iterator checking = address_binds.begin();
        address_binds.end() != checking;
        checking++) {
            if (checking->first == address) {
                nonce = checking->second;
                return true;
            }
       }
    return false;
}

bool CWallet::GetKeyFromPool(CPubKey& result, bool fAllowReuse)
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1)
        {
            if (fAllowReuse && vchDefaultKey.IsValid())
            {
                result = vchDefaultKey;
                return true;
            }
            if (IsLocked()) return false;
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

int64_t CWallet::GetOldestKeyPoolTime()
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    ReserveKeyFromKeyPool(nIndex, keypool);
    if (nIndex == -1)
        return GetTime();
    ReturnKey(nIndex);
    return keypool.nTime;
}

std::map<CTxDestination, int64_t> CWallet::GetAddressBalances()
{
    map<CTxDestination, int64_t> balances;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
        {
            CWalletTx *pcoin = &walletEntry.second;

            if (!pcoin->IsFinal() || !pcoin->IsTrusted())
                continue;

            if ((pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe() ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            {
                CTxDestination addr;
                if (!IsMine(pcoin->vout[i]))
                    continue;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, addr))
                    continue;

                int64_t n = pcoin->IsSpent(i) ? 0 : pcoin->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

set< set<CTxDestination> > CWallet::GetAddressGroupings()
{
    set< set<CTxDestination> > groupings;
    set<CTxDestination> grouping;

    BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
    {
        CWalletTx *pcoin = &walletEntry.second;

        if (pcoin->vin.size() > 0 && IsMine(pcoin->vin[0]))
        {
            // group all input addresses with each other
            BOOST_FOREACH(CTxIn txin, pcoin->vin)
            {
                CTxDestination address;
                if(!ExtractDestination(mapWallet[txin.prevout.hash].vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
            }

            // group change with input addresses
            BOOST_FOREACH(CTxOut txout, pcoin->vout)
                if (IsChange(txout))
                {
                    CWalletTx tx = mapWallet[pcoin->vin[0].prevout.hash];
                    CTxDestination txoutAddr;
                    if(!ExtractDestination(txout.scriptPubKey, txoutAddr))
                        continue;
                    grouping.insert(txoutAddr);
                }
            groupings.insert(grouping);
            grouping.clear();
        }

        // group lone addrs by themselves
        for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            if (IsMine(pcoin->vout[i]))
            {
                CTxDestination address;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    set< set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    map< CTxDestination, set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    BOOST_FOREACH(set<CTxDestination> grouping, groupings)
    {
        // make a set of all the groups hit by this new group
        set< set<CTxDestination>* > hits;
        map< CTxDestination, set<CTxDestination>* >::iterator it;
        BOOST_FOREACH(CTxDestination address, grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        set<CTxDestination>* merged = new set<CTxDestination>(grouping);
        BOOST_FOREACH(set<CTxDestination>* hit, hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        BOOST_FOREACH(CTxDestination element, *merged)
            setmap[element] = merged;
    }

    set< set<CTxDestination> > ret;
    BOOST_FOREACH(set<CTxDestination>* uniqueGrouping, uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

// ppcoin: check 'spent' consistency between wallet and txindex
// ppcoin: fix wallet spent state according to txindex
void CWallet::FixSpentCoins(int& nMismatchFound, int64_t& nBalanceInQuestion, bool fCheckOnly)
{
    nMismatchFound = 0;
    nBalanceInQuestion = 0;

    LOCK(cs_wallet);
    vector<CWalletTx*> vCoins;
    vCoins.reserve(mapWallet.size());
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        vCoins.push_back(&(*it).second);

    CTxDB txdb("r");
    BOOST_FOREACH(CWalletTx* pcoin, vCoins)
    {
        // Find the corresponding transaction index
        CTxIndex txindex;
        if (!txdb.ReadTxIndex(pcoin->GetHash(), txindex))
            continue;
        for (unsigned int n=0; n < pcoin->vout.size(); n++)
        {
            if (IsMine(pcoin->vout[n]) && pcoin->IsSpent(n) && (txindex.vSpent.size() <= n || txindex.vSpent[n].IsNull()))
            {
                printf("FixSpentCoins found lost coin %s SUM %s[%d], %s\n",
                    FormatMoney(pcoin->vout[n].nValue).c_str(), pcoin->GetHash().ToString().c_str(), n, fCheckOnly? "repair not attempted" : "repairing");
                nMismatchFound++;
                nBalanceInQuestion += pcoin->vout[n].nValue;
                if (!fCheckOnly)
                {
                    pcoin->MarkUnspent(n);
                    pcoin->WriteToDisk();
                }
            }
            else if (IsMine(pcoin->vout[n]) && !pcoin->IsSpent(n) && (txindex.vSpent.size() > n && !txindex.vSpent[n].IsNull()))
            {
                printf("FixSpentCoins found spent coin %s SUM %s[%d], %s\n",
                    FormatMoney(pcoin->vout[n].nValue).c_str(), pcoin->GetHash().ToString().c_str(), n, fCheckOnly? "repair not attempted" : "repairing");
                nMismatchFound++;
                nBalanceInQuestion += pcoin->vout[n].nValue;
                if (!fCheckOnly)
                {
                    pcoin->MarkSpent(n);
                    pcoin->WriteToDisk();
                }
            }
        }
    }
}

// ppcoin: disable transaction (only for coinstake)
void CWallet::DisableTransaction(const CTransaction &tx)
{
    if (!tx.IsCoinStake() || !IsFromMe(tx))
        return; // only disconnecting coinstake requires marking input unspent

    LOCK(cs_wallet);
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size() && IsMine(prev.vout[txin.prevout.n]))
            {
                prev.MarkUnspent(txin.prevout.n);
                prev.WriteToDisk();
            }
        }
    }
}

CPubKey CReserveKey::GetReservedKey()
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else
        {
            printf("CReserveKey::GetReservedKey(): Warning: Using default key instead of a new key, top up your keypool!");
            vchPubKey = pwallet->vchDefaultKey;
        }
    }
    assert(vchPubKey.IsValid());
    return vchPubKey;
}

bool CReserveKey::GetReservedKeyIn(CPubKey& pubkey)
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else {
            if (pwallet->vchDefaultKey.IsValid()) {
                printf("CReserveKey::GetReservedKey(): Warning: Using default key instead of a new key, top up your keypool!");
                vchPubKey = pwallet->vchDefaultKey;
            } else
                return false;
        }
    }
    assert(vchPubKey.IsValid());
    pubkey = vchPubKey;
    return true;
}


void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::GetAllReserveKeys(set<CKeyID>& setAddress) const
{
    setAddress.clear();

    CWalletDB walletdb(strWalletFile);

    LOCK2(cs_main, cs_wallet);
    BOOST_FOREACH(const int64_t& id, setKeyPool)
    {
        CKeyPool keypool;
        if (!walletdb.ReadPool(id, keypool))
            throw runtime_error("GetAllReserveKeyHashes() : read failed");
        assert(keypool.vchPubKey.IsValid());
        CKeyID keyID = keypool.vchPubKey.GetID();
        if (!HaveKey(keyID))
            throw runtime_error("GetAllReserveKeyHashes() : unknown key in key pool");
        setAddress.insert(keyID);
    }
}

void CWallet::UpdatedTransaction(const uint256 &hashTx)
{
    {
        LOCK(cs_wallet);
        // Only notify UI if this transaction is in this wallet
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
            NotifyTransactionChanged(this, hashTx, CT_UPDATED);
    }
}

void CWallet::GetKeyBirthTimes(std::map<CKeyID, int64_t> &mapKeyBirth) const {
    mapKeyBirth.clear();

    // get birth times for keys with metadata
    for (std::map<CKeyID, CKeyMetadata>::const_iterator it = mapKeyMetadata.begin(); it != mapKeyMetadata.end(); it++)
        if (it->second.nCreateTime)
            mapKeyBirth[it->first] = it->second.nCreateTime;

    // map in which we'll infer heights of other keys
    CBlockIndex *pindexMax = FindBlockByHeight(std::max(0, nBestHeight - 144)); // the tip can be reorganised; use a 144-block safety margin
    std::map<CKeyID, CBlockIndex*> mapKeyFirstBlock;
    std::set<CKeyID> setKeys;
    GetKeys(setKeys);
    BOOST_FOREACH(const CKeyID &keyid, setKeys) {
        if (mapKeyBirth.count(keyid) == 0)
            mapKeyFirstBlock[keyid] = pindexMax;
    }
    setKeys.clear();

    // if there are no such keys, we're done
    if (mapKeyFirstBlock.empty())
        return;

    // find first block that affects those keys, if there are any left
    std::vector<CKeyID> vAffected;
    for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); it++) {
        // iterate over all wallet transactions...
        const CWalletTx &wtx = (*it).second;
        std::map<uint256, CBlockIndex*>::const_iterator blit = mapBlockIndex.find(wtx.hashBlock);
        if (blit != mapBlockIndex.end() && blit->second->IsInMainChain()) {
            // ... which are already in a block
            int nHeight = blit->second->nHeight;
            BOOST_FOREACH(const CTxOut &txout, wtx.vout) {
                // iterate over all their outputs
                ::ExtractAffectedKeys(*this, txout.scriptPubKey, vAffected);
                BOOST_FOREACH(const CKeyID &keyid, vAffected) {
                    // ... and all their affected keys
                    std::map<CKeyID, CBlockIndex*>::iterator rit = mapKeyFirstBlock.find(keyid);
                    if (rit != mapKeyFirstBlock.end() && nHeight < rit->second->nHeight)
                        rit->second = blit->second;
                }
                vAffected.clear();
            }
        }
    }

    // Extract block timestamps for those keys
    for (std::map<CKeyID, CBlockIndex*>::const_iterator it = mapKeyFirstBlock.begin(); it != mapKeyFirstBlock.end(); it++)
        mapKeyBirth[it->first] = it->second->nTime - 7200; // block times can be 2h off
}
