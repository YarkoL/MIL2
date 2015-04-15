#include "delegatedata.h"


DelegateData::DelegateData(CNetAddr self,  CNetAddr other, CScript destination, uint64_t amount,  bool isDelegate)
    {
        _self = self;
        _other = other;
        _destination = destination;
        _amount = amount;
        _isDelegate = isDelegate;
    }



CNetAddr DelegateData::other() const
{
    return _other;
}

CScript DelegateData::destination() const
{
    return _destination;
}

void DelegateData::setDestination(const CScript &destination)
{
    _destination = destination;
}

uint64_t DelegateData::amount() const
{
    return _amount;
}



bool DelegateData::isDelegate() const
{
    return _isDelegate;
}


CNetAddr DelegateData::self() const
{
    return _self;
}


