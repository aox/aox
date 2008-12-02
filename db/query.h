// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef QUERY_H
#define QUERY_H

#include "global.h"
#include "database.h"
#include "stringlist.h"
#include "patriciatree.h"


class Row;
class UString;
class Transaction;
class EventHandler;
class PreparedStatement;


class Query
    : public Garbage
{
public:
    Query( EventHandler * = 0 );
    Query( const String &, EventHandler * );
    Query( const PreparedStatement &, EventHandler * );
    virtual ~Query() {}

    enum State {
        Inactive, Submitted, Executing, Completed, Failed
    };
    void setState( State );
    State state() const;
    bool failed() const;
    bool done() const;

    bool canFail() const;
    void allowFailure();

    bool canBeSlow() const;
    void allowSlowness();

    Transaction *transaction() const;
    void setTransaction( Transaction * );

    enum Format { Unknown = -1, Text = 0, Binary };
    Format format() const;

    void bind( uint, int );
    void bind( uint, uint );
    void bind( uint, int64 );
    void bind( uint, const String &, Format = Unknown );
    void bind( uint, const UString & );
    void bind( uint, const StringList & );
    void bind( uint, const class IntegerSet & );
    void bindNull( uint );
    void submitLine();

    void execute();

    class Value
        : public Garbage
    {
    private:
        uint n;
        bool null;
        String str;
        Query::Format fmt;

    public:
        Value( uint p )
            : n( p ), null( true )
        {}

        Value( uint p, const String &s, Query::Format f )
            : n( p ), null( false ), str( s ), fmt( f )
        {}

        int length() const {
            if ( null )
                return -1;
            return str.length();
        }
        String data() const { return str; }
        Query::Format format() const { return fmt; }
        uint position() const { return n; }

        bool operator <=( const Value &b ) {
            return n <= b.n;
        }
    };

    virtual String name() const;
    virtual String string() const;
    virtual void setString( const String & );

    typedef SortedList< Query::Value > InputLine;

    InputLine *values() const;
    List< InputLine > *inputLines() const;

    void setOwner( EventHandler * );
    EventHandler *owner() const;
    void notify();

    String description();

    String error() const;
    void setError( const String & );

    uint rows() const;
    void setRows( uint );
    bool hasResults() const;
    void addRow( Row * );
    Row *nextRow();

    class Log * log() const;

private:
    class QueryData *d;
};


class Column
    : public Garbage
{
public:
    enum Type { Unknown, Boolean, Integer, Bigint, Bytes, Timestamp, Null };

    Type type;
    String s;
    bool b;
    uint i;
    int64 bi;

    static String typeName( Type );
};


class Row
    : public Garbage
{
public:
    Row( const PatriciaTree<int> *, Column * );

    bool isNull( const char * ) const;
    int getInt( const char * ) const;
    int64 getBigint( const char * ) const;
    bool getBoolean( const char * ) const;
    String getString( const char * ) const;
    UString getUString( const char * ) const;
    bool hasColumn( const char * ) const;

private:
    const PatriciaTree<int> * names;
    const Column * data;

    const Column * fetch( const char *, Column::Type, bool ) const;
};


class PreparedStatement
    : public Garbage
{
public:
    PreparedStatement( const String & );
    String name() const;
    String query() const;

private:
    String n, q;
};


#endif
