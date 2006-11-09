// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "pgmessage.h"

#include "log.h"
#include "string.h"
#include "buffer.h"


/*! \class PgServerMessage pgmessage.h

    This is an abstract base class for PostgreSQL backend messages.

    PostgreSQL messages consist of a one-byte type code, a 32-bit number
    representing the size of the message, and a type-specific collection
    of n-bit integers in network byte order, NUL-terminated strings, and
    arbitrary sequences of bytes.

    Each message type is handled by a subclass of PgServerMessage, which
    provides the decodeByte/decodeInt32 and other functions to parse the
    message from an input buffer. The base class constructor removes the
    type and length specifications, leaving the subclass constructors to
    parse the rest of the message, and to throw a PgServerMessage::Error
    exception if they can't.
*/

/*! This function creates a new PgServerMessage, and decodes the type()
    and size() of the message from the Buffer \a b. It assumes that the
    Buffer contains a complete message, and leaves the rest of the data
    for a subclass constructor to deal with.
*/

PgServerMessage::PgServerMessage( Buffer *b )
    : buf( b )
{
    if ( b->size() < 5 )
        throw Syntax;

    n = 0;
    t = (*b)[0];

    l = (uint)(((*b)[1]<<24)|((*b)[2]<<16)|((*b)[3]<<8)|((*b)[4])) - 4;
    b->remove( 5 );
}


/*! \fn PgServerMessage::~PgServerMessage()
    This virtual destructor exists only for safe subclassing.
*/


/*! Returns the type of this PgServerMessage. */

char PgServerMessage::type() const
{
    return t;
}


/*! Returns the size of the contents of this PgServerMessage.
    (This does not include the size of the length field.)
*/

uint PgServerMessage::size() const
{
    return l;
}


/*! Returns a 16-bit integer in network byte order read and removed from
    the beginning of the input buffer. Throws a syntax error if it can't
    read two bytes without exceeding either the buffer or message size.
*/

int16 PgServerMessage::decodeInt16()
{
    if ( buf->size() < 2 || n+2 > l )
        throw Syntax;

    int16 v = ((*buf)[0] << 8) | (*buf)[1];
    buf->remove( 2 );
    n += 2;

    return v;
}


/*! Returns a 32-bit integer in network byte order read and removed from
    the beginning of the input buffer. Throws a syntax error if it can't
    read four bytes without exceeding either the buffer of message size.
*/

int PgServerMessage::decodeInt32()
{
    if ( buf->size() < 4 || n+4 > l )
        throw Syntax;

    int v = ( (*buf)[0] << 24 ) |
            ( (*buf)[1] << 16 ) |
            ( (*buf)[2] <<  8 ) |
            ( (*buf)[3]       );
    buf->remove( 4 );
    n += 4;

    return v;
}


/*! Removes a NUL-terminated string from the beginning of the input
    buffer, and returns it with the trailing NUL removed. Throws a
    syntax error if it doesn't find a NUL before the end of either
    the input buffer or the message.
*/

String PgServerMessage::decodeString()
{
    String s;

    uint i = 0;
    while ( i < buf->size() && i < l-n &&
            (*buf)[i] != '\0' )
        i++;

    if ( (*buf)[i] != '\0' )
        throw Syntax;

    s = buf->string( i );
    buf->remove( i+1 );
    n += i+1;

    return s;
}


/*! Returns one byte removed from the beginning of the input buffer.
    Throws a syntax error if it can't read a byte without exceeding
    either the buffer or message size.
*/

char PgServerMessage::decodeByte()
{
    if ( buf->size() < 1 || n+1 > l )
        throw Syntax;

    char c = (*buf)[0];
    buf->remove(1);
    n += 1;

    return c;
}


/*! Returns \a x bytes removed from the beginning of the input buffer.
    Throws a syntax error if it can't read \a x bytes without exceeding
    either the buffer or the message size.
*/

String PgServerMessage::decodeByten( uint x )
{
    if ( buf->size() < 1 || n+x > l )
        throw Syntax;

    String s = buf->string( x );
    buf->remove( x );
    n += x;

    return s;
}


/*! This function is used by subclasses to assert that they have decoded
    the entire contents of the message. If the size of the decoded data
    does not match the declared size of this message, end() throws an
    exception.
*/

void PgServerMessage::end()
{
    if ( n != l )
        throw Syntax;
}



/*! \class PgClientMessage pgmessage.h
    An abstract base class for PostgreSQL frontend messages.

    We treat client messages like server messages, dedicating a subclass
    to each message type. The subclass is expected to provide accessors
    to set the message fields, and an encodeData function that uses the
    appendByte/appendInt32 and other functions to assemble the encoded
    message. The base class prepends the message type and length.

    The message is sent by enqueue()ing it to a write buffer.
*/

/*! Creates a new PgClientMessage of type \a t. */

PgClientMessage::PgClientMessage( char t )
    : type( t )
{
}


/*! \fn PgClientMessage::~PgClientMessage()
    This virtual destructor exists only for safe subclassing.
*/


/*! Assembles a message, and appends the resulting packet (type, length,
    data) to \a buf. It relies on subclasses to "encodeData()" properly.
*/

void PgClientMessage::enqueue( Buffer *buf )
{
    String data;

    encodeData();
    data = msg;
    msg = "";

    if ( type != '\0' )
        msg.append( type );
    appendInt32( 4+data.length() );
    msg.append( data );

    buf->append( msg );
}


/*! \fn void PgClientMessage::encodeData()
    Every PgClientMessage subclass must implement this function, which
    is used by enqueue() to encode the type-specific part of messages.
*/


/*! Appends \a n to the message data as a 16-bit integer in network byte
    order.
*/

void PgClientMessage::appendInt16( int16 n )
{
    msg.append( (char) (n >> 8) );
    msg.append( (char) (n     ) );
}


/*! Appends \a n to the message data as a 32-bit integer in network byte
    order.
*/

void PgClientMessage::appendInt32( int n )
{
    msg.append( (char) (n >> 24) );
    msg.append( (char) (n >> 16) );
    msg.append( (char) (n >>  8) );
    msg.append( (char) (n      ) );
}


/*! Appends \a s to the message data as a NUL-terminated string. */

void PgClientMessage::appendString( const String & s )
{
    msg.append( s );
    msg.append( '\0' );
}


/*! Appends the bytes from \a s to the message data. */

void PgClientMessage::appendByten( const String & s )
{
    msg.append( s );
}


/*! Appends a single byte \a c to the message data. */

void PgClientMessage::appendByte( char c )
{
    msg.append( c );
}



/*! \class PgStartup pgmessage.h
    C: A client begins by sending a Startup message to the server.

    This message consists of an Int32 representing the desired protocol
    version, and any number of pairs of Strings representing an option
    name and value for the backend respectively. These can be set with
    the setOption() method.
*/

/*! \fn PgStartup::PgStartup()
    Creates a new startup message.
*/


void PgStartup::encodeData()
{
    appendInt32( 3<<16 | 0 );
    appendString( options );
}


/*! Sets the the parameter named \a key to the value \a val. */

void PgStartup::setOption( const String &key, const String &val )
{
    options.append( key  );
    options.append( '\0' );
    options.append( val  );
    options.append( '\0' );
}



/*! \class PgMessage pgmessage.h
    S: This is an error or notification message sent by the server.

    The message data consists of (Byte, String) pairs, terminated by a
    trailing NUL. The byte identifies the type of value that follows.
    (For example, 'M' is followed by the error message.)
*/

PgMessage::PgMessage( Buffer *b )
    : PgServerMessage( b )
{
    char type;

    while ( ( type = decodeByte() ) != '\0' ) {
        String s = decodeString();

        switch ( type ) {
        case 'S':
            if      ( s == "PANIC" )   S = Panic;
            else if ( s == "FATAL" )   S = Fatal;
            else if ( s == "ERROR" )   S = Error;
            else if ( s == "WARNING" ) S = Warning;
            else if ( s == "NOTICE" )  S = Notice;
            else if ( s == "DEBUG" )   S = Debug;
            else if ( s == "INFO" )    S = Info;
            else if ( s == "LOG" )     S = Log;
            else                       S = Unknown;
            break;
        case 'C': C = s; break;
        case 'M': M = s; break;
        case 'D': D = s; break;
        case 'H': H = s; break;
        case 'P': P = s; break;
        case 'W': W = s; break;
        case 'F': F = s; break;
        case 'L': L = s; break;
        case 'R': R = s; break;
        default:
            break;
        }
    }
    end();
}


/*! \fn PgMessage::Severity PgMessage::severity() const
    Returns the severity of a message, which may be any of the following
    values: Unknown, Panic, Fatal, Error, Warning, Notice, Debug, Info,
    Log.
*/

/*! \fn String PgMessage::code() const
    Returns (as a string) the SQLstate code associated with the message.
*/


/*! \fn String PgMessage::message() const
    Returns the contents of the message.
*/


/*! \fn String PgMessage::detail() const
    Returns a detailed description of the message(), if available, or
    an empty string otherwise.
*/


/*! \fn String PgMessage::hint() const
    Returns a hint to the user about what to do next, if available, or
    an empty string otherwise.
*/


/*! \fn String PgMessage::position() const
    Returns (as a string) the position in the query of whatever problem
    caused this message to be generated (or an empty string if no such
    thing was specified by the server).
*/


/*! \fn String PgMessage::where() const
    Returns a string describing where the error occurred, if available,
    or an empty string otherwise.
*/


/*! \fn String PgMessage::file() const
    Returns the name of the source file that generated the message, if
    available, or an empty string otherwise.
*/


/*! \fn String PgMessage::line() const
    Returns (as a string) the line number where the message was
    generated, if available, or an empty string otherwise.
*/


/*! \fn String PgMessage::routine() const
    Returns the name of the routine that generated this message, if
    available, or an empty string otherwise.
*/


/*! \class PgAuthRequest pgmessage.h
    S: An authentication request from the server.

    The message data consists of an Int32 code identifying the type of
    authentication requested (0=Success, 3=Password etc.), and, when a
    Crypt/MD5 password is requested, a salt to use for the encryption.
*/

PgAuthRequest::PgAuthRequest( Buffer *b )
    : PgServerMessage( b )
{
    uint l = size() - 4;
    t = (Type)decodeInt32();

    if ( ( t != Crypt && t != MD5 && l != 0 ) ||
         ( t == Crypt && l != 2 ) ||
         ( t == MD5 && l != 4 ) )
        throw Syntax;

    if ( l != 0 )
        s = decodeByten( l );
    end();
}


/*! \fn PgAuthRequest::Type PgAuthRequest::type() const
    Returns the type of this authentication request, which may be any of
    the following values: Success, Password, Crypt, MD5, Kerberos4,
    Kerberos5, Credential.
*/

/*! \fn String PgAuthRequest::salt() const
    Returns the salt value specified for this authentication request.
*/


/*! \class PgPasswordMessage pgmessage.h
    C: The client's response to an authentication request.

    This message contains a password (String), which may be encrypted if
    the server requested it.
*/

/*! Creates a password message containing the String \a s.
*/

PgPasswordMessage::PgPasswordMessage( const String &s )
    : PgClientMessage( 'p' ),
      p( s )
{
}


void PgPasswordMessage::encodeData()
{
    appendString( p );
}



/*! \class PgParameterStatus pgmessage.h
    S: This message communicates a parameter value to the client.

    The message data consists of two Strings: the name of a parameter,
    and its current value in the backend.
*/

PgParameterStatus::PgParameterStatus( Buffer *b )
    : PgServerMessage( b )
{
    k = decodeString();
    v = decodeString();
    end();
}


/*! \fn String PgParameterStatus::name()
    Returns the name of this parameter.
*/

/*! \fn String PgParameterStatus::value()
    Returns the value of this parameter.
*/



/*! \class PgKeyData pgmessage.h
    S: The server sends this data to enable clients to cancel requests.

    The message data consists of two Int32s: the backend pid and the key
    to use for future cancellation requests.
*/

PgKeyData::PgKeyData( Buffer *b )
    : PgServerMessage( b )
{
    p = decodeInt32();
    k = decodeInt32();
    end();
}


/*! \fn uint PgKeyData::pid()
    Returns the pid associated with this KeyData message.
*/

/*! \fn uint PgKeyData::key()
    Returns the key associated with this KeyData message.
*/



/*! \class PgParse pgmessage.h
    C: The client uses this to create prepared statements.

    This message contains a statement name (String), a query String, the
    number of pre-specified parameter types (Int16), and the OID (Int32)
    of each parameter type. (We never pre-specify parameter types here.)
*/

/*! Creates a Parse message for the statement \a s, to create a prepared
    statement named \a n. By default, \a n is empty.
*/

PgParse::PgParse( const String &s, const String &n )
    : PgClientMessage( 'P' ),
      name( n ), stmt( s ), types( 0 )
{
}


/*! Specifies that the parameters of this query have the types \a t.
*/

void PgParse::bindTypes( List< int > *t )
{
    types = t;
}


void PgParse::encodeData()
{
    appendString( name );
    appendString( stmt );

    if ( !types ) {
        appendInt16( 0 );
    }
    else {
        appendInt16( types->count() );
        List< int >::Iterator it( types );
        while ( it ) {
            appendInt32( *it );
            ++it;
        }
    }
}



/*! \class PgParseComplete pgmessage.h
    S: This indicates that a Parse message was successfully processed.

    This message contains no data.
*/

PgParseComplete::PgParseComplete( Buffer *b )
    : PgServerMessage( b )
{
    end();
}



/*! \class PgBind pgmessage.h
    C: Creates a portal by binding values to a prepared statement.

    This message contains the names of a portal to create and a prepared
    statement to bind values to (Strings); an Int16 count followed by an
    array of Int16 format codes; an Int16 count of values followed by an
    (Int32 length, Byten value) pair for each value; and an Int16 count
    followed by an array of Int16 result format codes.
*/

/*! Creates a message to Bind values to the prepared statement \a src in
    order to create a portal named \a dst. (By default, both \a src and
    \a dst are empty.)
*/

PgBind::PgBind( const String &src, const String &dst )
    : PgClientMessage( 'B' ),
      stmt( src ), portal( dst ), values( 0 )
{
}


/*! Binds the values in the list \a v to the prepared statement
    specified during construction.
*/

void PgBind::bind( List< Query::Value > *v )
{
    values = v;
}


void PgBind::encodeData()
{
    appendString( portal );
    appendString( stmt );

    if ( !values ) {
        appendInt16( 0 );
        appendInt16( 0 );
    }
    else {
        // Parameter formats.
        appendInt16( values->count() );
        List< Query::Value >::Iterator it( values );
        while ( it ) {
            appendInt16( it->format() );
            ++it;
        }

        // Parameter values.
        appendInt16( values->count() );
        it = values->first();
        while ( it ) {
            int n = it->length();
            appendInt32( n );
            if ( n > 0 )
                appendByten( it->data() );
            ++it;
        }
    }

    // All results should be binary-encoded.
    appendInt16( 1 );
    appendInt16( 1 );
}



/*! \class PgBindComplete pgmessage.h
    S: This indicates that a Bind message was successfully processed.

    This message contains no data.
*/

PgBindComplete::PgBindComplete( Buffer *b )
    : PgServerMessage( b )
{
    end();
}



/*! \class PgDescribe pgmessage.h
    C: Requests a description of a prepared statement or portal.

    This message consists of one byte ('S' for a prepared statement, and
    'P' for a portal) followed by a name (String).
*/

/*! Creates a Describe message for the name \a n (empty by default) of
    type \a t, which must be P or S ('P' by default).
*/

PgDescribe::PgDescribe( char t, const String &n )
    : PgClientMessage( 'D' ),
      type( t ), name( n )
{
}


void PgDescribe::encodeData()
{
    appendByte( type );
    appendString( name );
}



/*! \class PgNoData pgmessage.h
    S: The description of something that cannot return data.

    This is the server's response to a request to describe a prepared
    statement or portal that contains a query that cannot return data.
*/

PgNoData::PgNoData( Buffer *b )
    : PgServerMessage( b )
{
    end();
}



/*! \class PgParameterDescription pgmessage.h
    S: The description of a single parameter to a prepared statement.

    The message data consists of the 16-bit number of columns, followed
    by an Int32 type-oid for each column. We don't do anything with the
    message data yet.
*/

PgParameterDescription::PgParameterDescription( Buffer *b )
    : PgServerMessage( b )
{
    uint c = decodeInt16();
    while ( c-- ) {
        (void)decodeInt32();
    }
    end();
}



/*! \class PgRowDescription pgmessage.h
    S: The description of a single row of data.

    The message data contains the 16-bit number of columns, and tuples
    of (String name, Int32 table-oid, Int16 col-number, Int32 type-id,
    Int16 size, Int32 type-mod, Int16 format-code) for each column.
*/

PgRowDescription::PgRowDescription( Buffer *b )
    : PgServerMessage( b )
{
    uint c = decodeInt16();
    while ( c-- ) {
        Column *col = new Column;

        col->name = decodeString();
        col->table = decodeInt32();
        col->column = decodeInt16();
        col->type = decodeInt32();
        col->size = decodeInt16();
        col->mod = decodeInt32();
        col->format = decodeInt16();

        columns.append( col );
    }
    end();
}



/*! \class PgExecute pgmessage.h
    C: A request to execute a portal.

    This message contains the name (String) of a portal to execute, and
    the number of rows (Int32) to return from it.
*/

/*! Creates an Execute message for \a r rows of the portal named \a n.
    By default, \a n is empty and \a r is 0.
*/

PgExecute::PgExecute( const String &n, uint r )
    : PgClientMessage( 'E' ),
      name( n ), rows( r )
{
}


void PgExecute::encodeData()
{
    appendString( name );
    appendInt32( rows );
}



/*! \class PgDataRow pgmessage.h
    S: A row of data, as described by PgRowDescription.

    The message data contains the 16-bit number of columns, and pairs of
    (Int32 n, Byten) for each column. A column with length -1 is NULL.
*/

/*! This function constructs a new PgDataRow based on the contents of
    the Buffer \a b, and the PgRowDescription \a d.
*/

PgDataRow::PgDataRow( Buffer *b, const PgRowDescription *d )
    : PgServerMessage( b )
{
    uint c = decodeInt16();
    if ( c != d->columns.count() )
        // Is this really "Syntax"?
        throw Syntax;

    int i = 0;
    Column *columns = new Column[c];
    List< PgRowDescription::Column >::Iterator it( d->columns );
    while ( it ) {
        Column *cv = &columns[i];

        cv->name = it->name;
        switch ( it->type ) {
        case 16:    // BOOL
            cv->type = Column::Boolean;
            break;
        case 20:    // INT8
            cv->type = Column::Bigint;
            break;
        case 21:    // INT2
        case 23:    // INT4
            cv->type = Column::Integer;
            break;
        case 17:    // BYTEA
        case 18:    // CHAR
        case 25:    // TEXT
        case 1043:  // VARCHAR
            cv->type = Column::Bytes;
            break;
        default:
            //log( Log::Error,
            //     "PostgreSQL: Unknown field type " + fn( it->type ) );
            cv->type = Column::Unknown;
            break;
        }
        cv->length = decodeInt32();
        if ( cv->length > 0 )
            cv->value = decodeByten( cv->length );

        ++it;
        i++;
    }
    end();

    r = new Row( c, columns );
}


/*! Returns a pointer to a Row object based on the contents of the
    data row message.
*/

Row *PgDataRow::row() const
{
    return r;
}



/*! \class PgEmptyQueryResponse pgmessage.h
    S: The server's response to executing an empty query.

    This message does not contain any data.
*/

PgEmptyQueryResponse::PgEmptyQueryResponse( Buffer *b )
    : PgServerMessage( b )
{
    end();
}



/*! \class PgCommandComplete pgmessage.h
    S: Command completion notification.

    The message data contains the tag of the completed command (String).
*/

PgCommandComplete::PgCommandComplete( Buffer *b )
    : PgServerMessage( b )
{
    t = decodeString();
    end();
}


/*! \fn PgCommandComplete::tag()
    Returns the tag associated with this completion message.
*/



/*! \class PgFlush pgmessage.h
    C: The client sends this to request the server to flush its output
    buffer.

    This message contains no data.
*/

/*! \fn PgFlush::PgFlush()
    Creates a new PgFlush message.
*/

void PgFlush::encodeData()
{
}



/*! \class PgSync pgmessage.h
    C: The client sends this to mark the end of a query cycle.

    This message contains no data.
*/

/*! \fn PgSync::PgSync()
    Creates a new PgSync message.
*/

void PgSync::encodeData()
{
}



/*! \class PgReady pgmessage.h
    S: Ready for queries.

    The message data consists of a single byte backend status indicator.
*/

PgReady::PgReady( Buffer *b )
    : PgServerMessage( b )
{
    char t = decodeByte();

    if ( t == 'I' )
        s = Database::Idle;
    else if ( t == 'T' )
        s = Database::InTransaction;
    else if ( t == 'E' )
        s = Database::FailedTransaction;
    else
        throw Syntax;

    end();
}


/*! Returns the status of the server after this message, which may be
    any of Idle, InTransaction, or FailedTransaction.
*/

Database::State PgReady::state() const
{
    return s;
}



/*! \class PgQuery pgmessage.h
    C: A simple query.

    The message data consists of the query as a String.
*/

/*! Creates a new simple query message for the statement \a s.
*/

PgQuery::PgQuery( const String &s )
    : PgClientMessage( 'Q' ),
      stmt( s )
{
}


void PgQuery::encodeData()
{
    appendString( stmt );
}



/*! \class PgTerminate pgmessage.h
    C: Termination message.

    This message has no type-specific data, so we do nothing here.
*/

/*! \fn PgTerminate::PgTerminate()
    Creates a new termination message.
*/

void PgTerminate::encodeData()
{
}



/*! \class PgCopyInResponse pgmessage.h
    S: The backend is willing to accept CopyData messages.

    The message describes the expected format of the CopyData messages
    (text/binary format, number of columns, etc.)
*/

PgCopyInResponse::PgCopyInResponse( Buffer *b )
    : PgServerMessage( b )
{
    decodeByte();
    uint c = decodeInt16();
    while ( c-- > 0 )
        decodeInt16();
}



/*! \class PgCopyData pgmessage.h
    C: One row of data, formatted according to what the server expects
    (as described by the CopyInResponse).
*/

/*! Creates a new CopyData message for the Query \a q. */

PgCopyData::PgCopyData( const Query *q )
    : PgClientMessage( 'd' ),
      query( q )
{
}


void PgCopyData::encodeData()
{
    // Header: Signature, flags, extension length.
    appendByten( "PGCOPY\n\377\r\n" );
    appendByte( '\0' );
    appendInt32( 0 );
    appendInt32( 0 );

    // Tuples: Field count, fields.
    List< Query::InputLine >::Iterator it( *query->inputLines() );
    while ( it ) {
        Query::InputLine::Iterator v( it );

        appendInt16( it->count() );
        while ( v ) {
            int n = v->length();
            appendInt32( n );
            if ( n > 0 )
                appendByten( v->data() );
            ++v;
        }

        ++it;
    }

    // Trailer.
    appendInt16( -1 );
}



/*! \class PgCopyDone pgmessage.h
    C: Sent after the last of the CopyData messages.
*/

/*! \fn PgCopyDone::PgCopyDone()
    Creates a new CopyDone message.
*/

void PgCopyDone::encodeData()
{
}



/*! \class PgCopyFail pgmessage.h
    C: Sent if the frontend doesn't want to COPY.

    We don't bother with a sensible error message. This shouldn't ever
    be used anyway.
*/

/*! \fn PgCopyFail::PgCopyFail()
    Creates a new CopyFail message.
*/

void PgCopyFail::encodeData()
{
    appendString( "Nothing to COPY" );
}
