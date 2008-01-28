// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "egd.h"

#include "eventloop.h"
#include "entropy.h"
#include "buffer.h"
#include "log.h"


/*! \class EntropyProvider egd.h
    An EGD (entropy gathering device) for cryptlib.

    Cryptlib doesn't feel happy running in a constrained environment
    such as the chroot Archiveopteryx uses. It wants to run ntptrace
    and other commands to get entropy, and those commands aren't
    available.

    As a workaround, Archiveopteryx provides this EGD-compatible
    server which provides entropy from the Entropy class, and
    instructs Cryptlib that it can obtain entropy from this server via
    the EDG protocol.

*/



/*!  Constructs an entropy provider serving \a fd. */

EntropyProvider::EntropyProvider( int fd )
    : Connection( fd, EGDServer )
{
    if ( fd < 0 )
        return;

    setTimeoutAfter( 10 );
    EventLoop::global()->addConnection( this );
}


void EntropyProvider::react( Event e )
{
    if ( e == Read )
        process();
    else
        close();
}


/*! Serves the EGD protocol (as gleaned from egd.pl sources):

    Client sends a null byte to request the amount of entropy
    available. Archiveopteryx answers with 0x00 0x08 0x00, to say 2048
    bytes. This is a straight lie, motivated by a desire to have
    cryptlib work the same way as Archiveopteryx. If entropy-source is
    set to /dev/urandom (this is the default) Archiveopteryx will use
    true entropy if available, and fall back to using something
    weaker, but it will never block, not even if Cryptlib asks for it.

    Client sends 0x01 0xNN. Archiveopteryx answers with 0xNN followed
    by 0xNN bytes of entropy. (Unlike EGD, Archiveopteryx always
    provide as much data as Cryptlib wants.)

    Client sends 0x02 0xNN. Archiveopteryx behaves as for 0x01.

    Client sends 0x03 0xMM 0xLL, followed by 0xNN bytes of
    data. Archiveopteryx disregards it all.

    Client sends 0x04. Archiveopteryx returns 0x01 0x30 (a single
    "0", since we don't care to talk about PIDs).
*/

void EntropyProvider::process()
{
    Buffer * r = readBuffer();

    while ( r->size() >= 1 ) {
        char opcode = (*r)[0];
        char size = (*r)[1];
        switch( opcode ) {
        case 0:
            r->remove( 1 );
            enqueue( String( "\000\008\000", 3 ) );
            break;
        case 1:
        case 2:
            if ( r->size() < 2 )
                return;
            r->remove( 2 );
            writeBuffer()->append( &size, 1 );
            enqueue( Entropy::asString( size ) );
            log( "Served " + fn( size ) + " bytes of entropy to Cryptlib" );
            break;
        case 3:
            if ( r->size() < 2 + (uint)size )
                return;
            r->remove( 2 + size );
            break;
        case 4:
            r->remove( 1 );
            enqueue( String( "\0010", 2 ) );
            break;
        default:
            log( "Client sent non-EGD opcode: " + fn( opcode ), Log::Error );
            close();
            break;
        }
    }
}
