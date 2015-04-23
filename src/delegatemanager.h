#ifndef DELEGATEMANAGER_H
#define DELEGATEMANAGER_H

#include "net.h"
#include "script.h"


struct DelegateData {
    bool _isDelegate;
    CNetAddr _self;
    CNetAddr _other;
    CScript _destination;
    uint64_t _amount;
};

class DelegateManager
{
private:
    /*
    static std::map<
               std::vector<unsigned char>, //delegate key
               std::pair<
                   bool, //is Delegate?
                   std::list<
                       std::pair<CNetAddr, CNetAddr>, //self, other
                       std::pair<CScript, uint64_t>    //destination, amount
                   >
               >
           > delegate_data_map;

    */


    static std::map<std::vector<unsigned char>, DelegateData> delegate_data_map;

    DelegateManager();
    ~DelegateManager();

public:

    static std::vector<unsigned char> store(bool is_delegate,
                                             CNetAddr self,
                                             CNetAddr other,
                                             CScript destination,
                                             uint64_t amount);
    static bool remove(std::vector<unsigned char> key);
    static void clear();

    static bool isDelegate(std::vector<unsigned char> key);
    static CNetAddr self(std::vector<unsigned char> key);
    static CNetAddr other(std::vector<unsigned char> key);
    static CScript destination(std::vector<unsigned char> key);
    static uint64_t amount(std::vector<unsigned char> key);

    static bool setDestination(std::vector<unsigned char> key, CScript destination);
    static bool keyExists(std::vector<unsigned char> key);
    static bool getKeyFromOther(CNetAddr &addr, std::vector<unsigned char> &key);
};

#endif // DELEGATEMANAGER_H
