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
        Inactive, Submitted, Preparing, Executing, Completed, Failed
    };
    void setState( State );
    State state() const;
    bool failed() const;
    bool done() const;

    Transaction *transaction() const;
    void setTransaction( Transaction * );

    class Value {
    public:
        Value( int p, const String &s )
            : n( p ), d( s )
        {}

        String data() const;

        bool operator <=( const Value &b ) {
            return n <= b.n;
        }

    private:
        int n;
        String d;
    };

    void bind( uint, const String & );
    void bind( uint, int );
    void execute();

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


class PreparedStatement
    : public Query
{
public:
    PreparedStatement( const String &, const String &, EventHandler * );
    String name() const;

private:
    String n;
};


#endif
