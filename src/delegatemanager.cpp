#include "delegatemanager.h"
#include "net.h"

std::map<std::vector<unsigned char>, DelegateData> DelegateManager::delegate_data_map;

DelegateManager::DelegateManager()
{
}

std::vector<unsigned char> DelegateManager::store(bool is_delegate,
        CNetAddr self,
        CNetAddr other,
        CScript destination,
        uint64_t amount
) {

    std::vector<unsigned char> key(sizeof(uint64_t));
    do {
        uint64_t const numeric = GetRand(std::numeric_limits<uint64_t>::max());
        memcpy(key.data(), &numeric, sizeof(numeric));
        if (delegate_data_map.end() == delegate_data_map.find(key)) {
            break;
        }
    } while (true);

   DelegateData delegateData;

   delegateData._isDelegate = is_delegate;
   delegateData._self = self;
   delegateData._other = other;
   delegateData._destination = destination;
   delegateData._amount = amount;

   delegate_data_map[key] = delegateData;
/*
    std::make_pair(self,   //second.first.first
                   other); //second.first.second;

    std::make_pair(destination, //second.second.first
                   amount);      //second.second.second

    delegate_data_map[key] = std::make_pair(
        is_delegate, //first
        std::make_pair(

        )
    );
*/
    return key;
}

bool DelegateManager::remove(std::vector<unsigned char> key) {
    return (delegate_data_map.erase(key) > 0)? true : false;
}

void DelegateManager::clear() {
    delegate_data_map.clear();
}

bool DelegateManager::isDelegate(std::vector<unsigned char> key) {
    return delegate_data_map[key]._isDelegate;
}

CNetAddr DelegateManager::self(std::vector<unsigned char> key) {
    return delegate_data_map[key]._self;
}

CNetAddr DelegateManager::other(std::vector<unsigned char> key) {
    return delegate_data_map[key]._other;
}

CScript DelegateManager::destination(std::vector<unsigned char> key) {
    return delegate_data_map[key]._destination;
}

bool DelegateManager::setDestination(std::vector<unsigned char> key, CScript destination) {
    if (delegate_data_map.count(key) > 0) {
        delegate_data_map[key]._destination = destination;
        return true;
    }
    return false;
}

uint64_t DelegateManager::amount(std::vector<unsigned char> key) {
    return delegate_data_map[key]._amount;
}

bool DelegateManager::keyExists(std::vector<unsigned char> key) {
    return (delegate_data_map.count(key) > 0)? true : false;
}

bool DelegateManager::getKeyFromOther(CNetAddr &addr, std::vector<unsigned char>& key) {
    std::map<std::vector<unsigned char>, DelegateData>::const_iterator it;
    for (it = delegate_data_map.begin(); it != delegate_data_map.end(); ++it){
        if (it->second._other == addr) {
            key = it->first;
            return true;
        }
    }
    return  false;
}
