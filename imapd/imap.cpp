#include "imap.h"

#include "command.h"

#include <test.h>
#include <buffer.h>
#include <arena.h>
#include <list.h>

#include <time.h>


class IMAPData {
public:
    IMAPData(): parsedCommandArena( 0 ),
                readingLiteral( false ), literalSize( 0 ),
                args( 0 ),
                state( IMAP::NotAuthenticated )
    {}

    Arena * parsedCommandArena;
    bool readingLiteral;
    uint literalSize;
    List<String> * args;
    IMAP::State state;
};


/*! \class IMAP

  \brief The IMAP class implements the IMAP server seen by clients.

  Most of IMAP functionality is in the command handlers, but this
  class contains the top-level responsibility and functionality. This
  class reads commands from its network connection, does basic
  parsing and creates command handlers as necessary.
*/


/*! Creates a basic IMAP connection */

IMAP::IMAP(int s)
    : Connection(s), d(0)
{
    d = new IMAPData;

    setReadBuffer( new Buffer( fd() ) );
    setWriteBuffer( new Buffer( fd() ) );
    writeBuffer()->append("* OK - ne plus ultra\r\n");
    setTimeout( time(0) + 20 );
}


/*! Destroys the object and closes its network connection. */

IMAP::~IMAP()
{
    delete d;
}


/*! Handles incoming data and timeouts. */

int IMAP::react(Event e)
{
    int result = 1;
    switch (e) {
    case Connection::Read:
        result = parse();
        break;
    case Connection::Timeout:
        writeBuffer()->append("* BAD autologout\r\n");
        result = 0;
        break;
    }
    if ( state() == Logout )
        result = 0;
    if ( result )
        setTimeout( time(0) + 20 );
    else
        writeBuffer()->write();
    return result;
}


int IMAP::parse()
{
    if ( !d->parsedCommandArena )
        d->parsedCommandArena = new Arena;
    if ( !d->args )
        d->args = new List<String>;
    // XXX: must set the right arena
    Buffer * r = readBuffer();
    while( true ) {
        if ( d->readingLiteral ) {
            if ( r->size() >= d->literalSize ) {
                d->args->append( r->string( d->literalSize ) );
                r->remove( d->literalSize );
                d->readingLiteral = false;
            }
            else {
                return true; // better luck next time
            }
        }
        else {
            // this is a little evil, isn't it? Buffer::canReadLine()
            // sounds like a good idea after all.
            uint i = 0;
            while( i < r->size() && (*r)[i] != 10 )
                i++;
            if ( (*r)[i] == 10 ) {
                // we have a line; read it and consider literals
                uint j = i;
                if ( i > 0 && (*r)[i-1] == 13 )
                    j--;
                String * s = r->string( j );
                d->args->append( s );
                r->remove( i + 1 ); // string + trailing lf
                if ( s->endsWith( "}" ) ) {
                    i = s->length()-2;
                    bool plus = false;
                    if ( (*s)[i] == '+' ) {
                        plus = true;
                        i--;
                    }
                    j = i;
                    while( i > 0 && (*s)[i] >= '0' && (*s)[i] <= '9' )
                        i--;
                    if ( (*s)[i] == '{' ) {
                        d->readingLiteral = true;
                        bool ok;
                        d->literalSize = s->mid( i+1, j-i-1 ).number( &ok );
                        // if ( ok && size > 99999999 ) ok = false; ? perhaps?
                        if ( !ok ) {
                            writeBuffer()->append( "* BAD literal, BAD\r\n" );
                            return false;
                        }
                        if ( ok && !plus )
                            writeBuffer()->append( "+\r\n" );
                    }
                }
                if ( !d->readingLiteral )
                    addCommand();
            }
            else {
                return true; // better luck next time
            }
        }
    }
}


/*! Does preliminary parsing and adds a new Command object. At some
  point, that object may be executed - we don't care about that for
  the moment.
*/

void IMAP::addCommand()
{
    List<String> * args = d->args;
    d->args = new List<String>;

    String * s = args->first();

    // pick up the tag
    uint i = (uint)-1;
    uchar c;
    do {
        i++;
        c = (*s)[i];
    } while( i < s->length() &&
             c < 128 && c > ' ' && c != '+' &&
             c != '(' && c != ')' && c != '{' &&
             c != '%' && c != '%' );
    if ( i < 1 || c != ' ' ) {
        writeBuffer()->append( "* BAD tag\r\n" );
        return;
    }
    String tag = s->mid( 0, i );

    // pick up the command
    uint j = i+1;
    do {
        i++;
        c = (*s)[i];
    } while( i < s->length() &&
             c < 128 && c > ' ' &&
             c != '(' && c != ')' && c != '{' &&
             c != '%' && c != '%' &&
             c != '"' && c != '\\' &&
             c != ']' );
    if ( i == j ) {
        writeBuffer()->append( "* BAD no command\r\n" );
        return;
    }
    String command = s->mid( j, i-j );

    // evil hack: skip past a space if there is one, for ease of
    // parsing by the Command classes.
    if ( (*s)[i] == ' ' )
        i++;

    // write the new string into the one in the list
    *s = s->mid( i );

    Command * cmd = Command::create( this, command, tag, args );
    if ( cmd ) {
        cmd->parse();
        if ( cmd->ok() )
            cmd->execute();
        cmd->emitResponses();
    }
    else {
        String tmp( tag );
        tmp += " BAD command unknown: ";
        tmp += command;
        tmp += "\r\n";
        writeBuffer()->append( tmp );
    }
}


static class IMAPTest : public Test {
public:
    IMAPTest() : Test( 500 ) {}
    void test() {
        
    }
} imapTest;




/*! Returns the current state of this IMAP session, which is one of
  NotAuthenticated, Authenticated, Selected and Logout.
*/

IMAP::State IMAP::state() const
{
    return d->state;
}


/*! Sets this IMAP connection to be in state \a s. The initial value
  is NotAuthenticated.
*/

void IMAP::setState( State s )
{
    d->state = s;
}
