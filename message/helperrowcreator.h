// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef HELPERROWCREATOR_H
#define HELPERROWCREATOR_H

#include "injector.h"
#include "estringlist.h"
#include "dict.h"


class HelperRowCreator
    : public EventHandler
{
public:
    HelperRowCreator( const EString &, class Transaction *, const EString & );

    bool done() const;

    void execute();

    uint id( const EString & );

protected:
    void add( const EString &, uint );

private:
    virtual Query * makeSelect() = 0;
    virtual void processSelect( Query * );
    virtual Query * makeCopy() = 0;

private:
    class HelperRowCreatorData * d;
};


class FlagCreator
    : public HelperRowCreator
{
public:
    FlagCreator( const EStringList &, class Transaction * );

private:
    Query * makeSelect();
    Query * makeCopy();

private:
    EStringList names;
};


class FieldNameCreator
    : public HelperRowCreator
{
public:
    FieldNameCreator( const EStringList &, class Transaction * );

private:
    Query * makeSelect();
    Query * makeCopy();

private:
    EStringList names;
};


class AnnotationNameCreator
    : public HelperRowCreator
{
public:
    AnnotationNameCreator( const EStringList &, class Transaction * );

private:
    Query * makeSelect();
    Query * makeCopy();

private:
    EStringList names;
};


class AddressCreator
    : public HelperRowCreator
{
public:
    AddressCreator( Dict<Address> *, class Transaction * );
    AddressCreator( Address *, class Transaction * );
    AddressCreator( List<Address> *, class Transaction * );

    static EString key( Address * );

private:
    Query * makeSelect();
    void processSelect( Query * );
    Query * makeCopy();

private:
    uint param( Dict<uint> *, const EString &, uint &, Query * );

private:
    Dict<Address> * a;
    List<Address> asked;
};




#endif
