#ifndef PGMESSAGE_H
#define PGMESSAGE_H

#include "global.h"
#include "string.h"
#include "list.h"
#include "query.h"

class Buffer;


class PgServerMessage {
public:
    PgServerMessage( Buffer *b );
    virtual ~PgServerMessage() {}

    enum Error { Syntax };

protected:
    Buffer * buf;
    uint l, n;
    char t;

    char type() const;
    uint size() const;
    int16 decodeInt16();
    int decodeInt32();
    char decodeByte();
    String decodeString();
    String decodeByten( uint );
    void end();
};


class PgClientMessage {
public:
    PgClientMessage( char t );
    virtual ~PgClientMessage() {}

    void enqueue( Buffer * );

protected:
    char type;
    String msg;

    void appendInt16( int16 );
    void appendInt32( int );
    void appendByte( char );
    void appendByten( const String & );
    void appendString( const String & );

    virtual void encodeData() = 0;
};


class PgStartup
    : public PgClientMessage
{
public:
    PgStartup() : PgClientMessage( '\0' ) {}
    void setOption( const String &, const String & );

private:
    String options;
    void encodeData();
};


class PgMessage
    : public PgServerMessage
{
public:
    PgMessage( Buffer * );

    enum Severity {
        Unknown, Panic, Fatal, Error, Warning, Notice, Debug, Info, Log
    };
    Severity severity() const { return S; }

    String code()     const { return C; }
    String message()  const { return M; }
    String detail()   const { return D; }
    String hint()     const { return H; }
    String position() const { return P; }
    String where()    const { return W; }
    String file()     const { return F; }
    String line()     const { return L; }
    String routine()  const { return R; }

private:
    Severity S;
    String C, M, D, H, P, W, F, L, R;
};


class PgAuthRequest
    : public PgServerMessage
{
public:
    PgAuthRequest( Buffer * );

    enum Type {
        Success,
        Kerberos4, Kerberos5,
        Password, Crypt, MD5,
        Credential
    };

    Type type()   const { return t; }
    String salt() const { return s; }

private:
    Type t;
    String s;
};


class PgPasswordMessage
    : public PgClientMessage
{
public:
    PgPasswordMessage( const String & );

private:
    void encodeData();

    String p;
};


class PgParameterStatus
    : public PgServerMessage
{
public:
    PgParameterStatus( Buffer * );

    String name() { return k; }
    String value() { return v; }

private:
    String k, v;
};


class PgKeyData
    : public PgServerMessage
{
public:
    PgKeyData( Buffer * );

    uint pid() { return p; }
    uint key() { return k; }

private:
    uint p, k;
};


class PgParse
    : public PgClientMessage
{
public:
    PgParse( const String &, const String & = "" );

private:
    void encodeData();

    String name;
    String stmt;
};


class PgParseComplete
    : public PgServerMessage
{
public:
    PgParseComplete( Buffer * );
};


class PgBind
    : public PgClientMessage
{
public:
    PgBind( const String & = "", const String & = "" );
    void bind( List< Query::Value > * );

private:
    void encodeData();

    String stmt;
    String portal;
    List< Query::Value > *values;
};


class PgBindComplete
    : public PgServerMessage
{
public:
    PgBindComplete( Buffer * );
};


class PgDescribe
    : public PgClientMessage
{
public:
    PgDescribe( char = 'P', const String & = "" );

private:
    void encodeData();

    char type;
    String name;
};


class PgNoData
    : public PgServerMessage
{
public:
    PgNoData( Buffer * );
};


class PgRowDescription
    : public PgServerMessage
{
public:
    PgRowDescription( Buffer * );

    class Column {
    public:
        String name;
        uint table, column, type, size, mod, format;
    };

    List< Column > columns;
};


class PgExecute
    : public PgClientMessage
{
public:
    PgExecute( const String & = "", uint = 0 );

private:
    void encodeData();

    String name;
    uint rows;
};


class PgDataRow
    : public PgServerMessage
{
public:
    PgDataRow( Buffer * );

    class Value {
    public:
        int length;
        String value;
    };

    List< Value > columns;
};


class PgEmptyQueryResponse
    : public PgServerMessage
{
public:
    PgEmptyQueryResponse( Buffer * );
};


class PgCommandComplete
    : public PgServerMessage
{
public:
    PgCommandComplete( Buffer * );

    String tag() { return t; }

private:
    String t;
};


class PgSync
    : public PgClientMessage
{
public:
    PgSync() : PgClientMessage( 'S' ) {}

private:
    void encodeData();
};


class PgReady
    : public PgServerMessage
{
public:
    PgReady( Buffer * );

    enum Status { Idle, Transaction, Failed };
    Status status() const { return s; }

private:
    Status s;
};


class PgQuery
    : public PgClientMessage
{
public:
    PgQuery( const String & );

private:
    void encodeData();

    String stmt;
};


class PgTerminate
    : public PgClientMessage
{
public:
    PgTerminate() : PgClientMessage( 'X' ) {}

private:
    void encodeData();
};

#endif
