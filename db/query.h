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

    bool canFail() const;
    void allowFailure();

    Transaction *transaction() const;
    void setTransaction( Transaction * );

    enum Format { Text, Binary };

    void bind( uint, int, Format = Text );
    void bind( uint, const String &, Format = Text );
    void bindNull( uint );
    void submitLine();

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

    typedef SortedList< Query::Value > InputLine;

    InputLine *values() const;
    List< InputLine > *inputLines() const;

    EventHandler *owner() const;
    void notify();

    String description();

    String error() const;
    void setError( const String & );

    uint rows() const;
    bool hasResults() const;
    void addRow( Row * );
    Row *nextRow();

private:
    class QueryData *d;
};


class Column {
public:
    enum Type { Unknown, Boolean, Integer, Bytes };

    String name;
    Type type;
    int length;
    String value;

    static String typeName( Type );
};


class Row {
public:
    Row( uint, Column * );

    bool isNull( uint ) const;
    bool isNull( const char * ) const;

    int getInt( uint ) const;
    int getInt( const char * ) const;

    bool getBoolean( uint ) const;
    bool getBoolean( const char * ) const;

    String getString( uint ) const;
    String getString( const char * ) const;

private:
    uint n;
    Column *columns;

    int findColumn( const char * ) const;
    bool badFetch( uint, Column::Type = Column::Unknown ) const;
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
