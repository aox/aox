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

    Transaction *transaction() const;
    void setTransaction( Transaction * );

    enum Format { Text, Binary };

    void bind( uint, int );
    void bind( uint, const String &, Format = Text );
    void execute();

    class Value {
    private:
        int n;
        String d;
        Query::Format f;

    public:
        Value( int p, const String &s, Query::Format fmt )
            : n( p ), d( s ), f( fmt )
        {}

        String data() const { return d; }
        Query::Format format() const { return f; }

        bool operator <=( const Value &b ) {
            return n <= b.n;
        }
    };

    virtual String name() const;
    virtual String string() const;
    List< Value > *values() const;

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
    Row();

    class Column {
    public:
        String name;
        Database::Type type;
        int length;
        String value;
    };

    void append( Column * );
    String *getString( const String & );
    int *getInt( const String & );

private:
    List< Column > columns;
    List< Column >::Iterator findColumn( const String & );
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
