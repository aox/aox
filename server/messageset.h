// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MESSAGESET_H
#define MESSAGESET_H

#include "string.h"


class MessageSet {
public:
    MessageSet();
    MessageSet( const MessageSet & );

    MessageSet& operator=( const MessageSet & );

    uint smallest() const;
    uint largest() const;
    uint count() const;
    bool isEmpty() const;
    bool isRange() const;

    bool contains( uint ) const;

    uint value( uint ) const;
    uint index( uint ) const;

    String where( const String & table = "" ) const;

    void add( uint, uint );
    void add( uint n ) { add( n, n ); }
    void add( const MessageSet & );

    void remove( uint );
    void remove( const MessageSet & );
    void clear();

    MessageSet intersection( const MessageSet & ) const;

private:
    class SetData * d;
};


#endif
