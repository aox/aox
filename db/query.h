// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef QUERY_H
#define QUERY_H

#include "global.h"
#include "string.h"
#include "list.h"
#include "database.h"

class Row;
class Transaction;
class EventHandler;
class PreparedStatement;


class Query {
public:
    Query( EventHandler * );
    Query( const String &, EventHandler * );
    Query( const PreparedStatement &, EventHandler * );
    virtual ~Query() {}

    enum Type { Begin, Execute, Commit, Rollback };
    Type type() const;

    enum State {
        Inactive, Submitted, Executing, Completed, Failed
    };
    void setState( State );
    State state() const;
    bool failed() const;
    bool done() const;

    void setStartUpQuery( bool );
    bool isStartUpQuery() const;
    static bool isStartingUp();

    Transaction *transaction() const;
    void setTransaction( Transaction * );

    enum Format { Text, Binary };

    void bind( uint, int );
    void bind( uint, const String &, Format = Text );
    void bindNull( uint );
    void execute();

    class Value {
    private:
        int n;
        bool null;
        String str;
        Query::Format fmt;

    public:
        Value( int p )
            : n( p ), null( true )
        {}

        Value( int p, const String &s, Query::Format f )
            : n( p ), null( false ), str( s ), fmt( f )
        {}

        int length() const {
            if ( null )
                return -1;
            return str.length();
        }
        String data() const { return str; }
        Query::Format format() const { return fmt; }

        bool operator <=( const Value &b ) {
            return n <= b.n;
        }
    };

    virtual String name() const;
    virtual String string() const;
    List< Value > *values() const;

    List< int > *types() const;
    void appendType( int );

    EventHandler *owner() const;
    void notify();

    String error() const;
    void setError( const String & );

    uint rows() const;
    bool hasResults() const;
    void addRow( Row * );
    Row *nextRow();

private:
    class QueryData *d;
};


class Row {
public:
    class Column {
    public:
        String name;
        Database::Type type;
        int length;
        String value;
    };

    Row( uint, Column * );

    bool isNull( uint ) const;
    bool isNull( const String & ) const;

    int getInt( uint ) const;
    int getInt( const String & ) const;

    bool getBoolean( uint ) const;
    bool getBoolean( const String & ) const;

    String getString( uint ) const;
    String getString( const String & ) const;

private:
    uint n;
    Column *columns;

    int findColumn( const String & ) const;
    bool badFetch( uint, Database::Type = Database::Unknown ) const;
};


class PreparedStatement {
public:
    PreparedStatement( const String & );
    String name() const;
    String query() const;

private:
    String n, q;
};


#endif
