// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef HELPERROWCREATOR_H
#define HELPERROWCREATOR_H

#include "injector.h"
#include "estringlist.h"
#include "ustringlist.h"
#include "dict.h"


class HelperRowCreator
    : public EventHandler
{
public:
    HelperRowCreator( const EString &, class Transaction *, const EString & );

    bool done() const;

    void execute();

    virtual uint id( const EString & );

    bool inserted() const;

protected:
    virtual void add( const EString &, uint );

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

    EStringList * allFlags() { return &names; }

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

    void execute();

private:
    Query * makeSelect();
    void processSelect( Query * );
    Query * makeCopy();

private:
    uint param( Dict<uint> *, const EString &, uint &, Query * );

private:
    Dict<Address> * a;
    List<Address> asked;
    bool bulk;
    bool decided;
    Transaction * base;
    Transaction * sub;
    Query * insert;
    Query * obtain;
};


class BaseSubjectCreator
    : public HelperRowCreator
{
public:
    BaseSubjectCreator( const class UStringList &, class Transaction * );

private:
    Query * makeSelect();
    Query * makeCopy();

private:
    UStringList subjects;
};


class ThreadRootCreator
    : public HelperRowCreator
{
public:
    class Message
        : public Garbage
    {
    public:
        Message(): Garbage() {}

        virtual EStringList references() const = 0;
        virtual EString messageId() const = 0;

        virtual void mergeThreads( uint, uint ) = 0;
    };

    ThreadRootCreator( List<class ThreadRootCreator::Message> *,
                       class Transaction * );

    class ThreadNode
        : public Garbage
    {
    public:
        ThreadNode( const EString & messageId )
            : Garbage(), id( messageId ), parent( 0 ), trid( 0 ) {}

        EString id;
        class ThreadNode * parent;
        uint trid;
    };

private:
    Query * makeSelect();
    Query * makeCopy();

    uint id( const EString & );
    void add( const EString &, uint );

private:
    List<Message> * messages;
    Dict<ThreadNode> * nodes;
    bool first;
};



#endif
