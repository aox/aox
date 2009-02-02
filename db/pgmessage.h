// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef PGMESSAGE_H
#define PGMESSAGE_H

#include "database.h"
#include "estring.h"
#include "query.h"
#include "list.h"

class Buffer;


class PgServerMessage
    : public Garbage
{
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
    EString decodeString();
    EString decodeByten( uint );
    void end();
};


class PgClientMessage
    : public Garbage
{
public:
    PgClientMessage( char t );
    virtual ~PgClientMessage() {}

    void enqueue( Buffer * );

protected:
    char type;
    EString msg;

    void appendInt16( int16 );
    void appendInt32( int );
    void appendByte( char );
    void appendByten( const EString & );
    void appendString( const EString & );

    virtual void encodeData() = 0;
};


class PgStartup
    : public PgClientMessage
{
public:
    PgStartup() : PgClientMessage( '\0' ) {}
    void setOption( const EString &, const EString & );

private:
    EString options;
    void encodeData();
};


class PgCancel
    : public PgClientMessage
{
public:
    PgCancel( class PgKeyData * key )
        : PgClientMessage( '\0' ), k( key )
    {}

private:
    class PgKeyData * k;
    void encodeData();
};


class PgMessage
    : public PgServerMessage
{
public:
    PgMessage( Buffer * );

    enum Type { Notification, Error };

    Type type()       const { return t; }
    EString severity() const { return S; }
    EString code()     const { return C; }
    EString message()  const { return M; }
    EString detail()   const { return D; }
    EString hint()     const { return H; }
    EString position() const { return P; }
    EString where()    const { return W; }
    EString file()     const { return F; }
    EString line()     const { return L; }
    EString routine()  const { return R; }

private:
    Type t;
    EString S, C, M, D, H, P, W, F, L, R;
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
    EString salt() const { return s; }

private:
    Type t;
    EString s;
};


class PgPasswordMessage
    : public PgClientMessage
{
public:
    PgPasswordMessage( const EString & );

private:
    void encodeData();

    EString p;
};


class PgParameterStatus
    : public PgServerMessage
{
public:
    PgParameterStatus( Buffer * );

    EString name() { return k; }
    EString value() { return v; }

private:
    EString k, v;
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
    PgParse( const EString &, const EString & = "" );
    void bindTypes( List< int > * );

private:
    void encodeData();

    EString name;
    EString stmt;
    List< int > *types;
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
    PgBind( const EString & = "", const EString & = "" );
    void bind( List< Query::Value > * );

private:
    void encodeData();

    EString stmt;
    EString portal;
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
    PgDescribe( char = 'P', const EString & = "" );

private:
    void encodeData();

    char type;
    EString name;
};


class PgNoData
    : public PgServerMessage
{
public:
    PgNoData( Buffer * );
};


class PgParameterDescription
    : public PgServerMessage
{
public:
    PgParameterDescription( Buffer * );
};


class PgRowDescription
    : public PgServerMessage
{
public:
    PgRowDescription( Buffer * );

    class Column
        : public Garbage
    {
    public:
        EString name;
        int table, column, type, size, mod, format, column2;
    };

    List<Column> columns;
    PatriciaTree<int> names;
    uint count;
};


class PgExecute
    : public PgClientMessage
{
public:
    PgExecute( const EString & = "", uint = 0 );

private:
    void encodeData();

    EString name;
    uint rows;
};


class PgDataRow
    : public PgServerMessage
{
public:
    PgDataRow( Buffer *, const PgRowDescription * );
    Row *row() const;

private:
    Row *r;
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

    EString tag() { return t; }

private:
    EString t;
};


class PgSync
    : public PgClientMessage
{
public:
    PgSync() : PgClientMessage( 'S' ) {}

private:
    void encodeData();
};


class PgFlush
    : public PgClientMessage
{
public:
    PgFlush() : PgClientMessage( 'H' ) {}

private:
    void encodeData();
};


class PgReady
    : public PgServerMessage
{
public:
    PgReady( Buffer * );

    Database::State state() const;

private:
    Database::State s;
};


class PgQuery
    : public PgClientMessage
{
public:
    PgQuery( const EString & );

private:
    void encodeData();

    EString stmt;
};


class PgTerminate
    : public PgClientMessage
{
public:
    PgTerminate() : PgClientMessage( 'X' ) {}

private:
    void encodeData();
};


class PgCopyInResponse
    : public PgServerMessage
{
public:
    PgCopyInResponse( Buffer * );

private:
};


class PgCopyData
    : public PgClientMessage
{
public:
    PgCopyData( const Query * );

private:
    void encodeData();
    void encodeText();
    void encodeBinary();
    const Query *query;
};


class PgCopyDone
    : public PgClientMessage
{
public:
    PgCopyDone() : PgClientMessage( 'c' ) {}

private:
    void encodeData();
};


class PgCopyFail
    : public PgClientMessage
{
public:
    PgCopyFail() : PgClientMessage( 'f' ) {}

private:
    void encodeData();
};


class PgNotificationResponse
    : public PgServerMessage
{
public:
    PgNotificationResponse( Buffer * );

    EString name() const;
    EString source() const;
    uint pid() const;

private:
    EString n, s;
    uint p;
};


#endif
