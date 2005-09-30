// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "thread.h"


class ThreadData
    : public Garbage
{
public:
    ThreadData()
    {}

    String mechanism;
};


/*! \class Thread thread.h
    Implements the THREAD extension described in
    draft-ietf-imapext-sort.
*/


/*! Creates a new handler for THREAD (or UID THREAD, if \a u is true).
*/

Thread::Thread( bool u )
    : Search( u ),
      d( new ThreadData )
{
}


void Thread::parse()
{
    space();
    d->mechanism = atom().lower();
    if ( d->mechanism != "orderedsubject" )
        error( Bad, "Unsupported THREAD mechanism: " + d->mechanism );
    space();
    setCharset( astring() );

    space();
    parseKey();
    while ( nextChar() == ' ' ) {
        space();
        parseKey();
    }
    end();

    prepare();
}


void Thread::execute()
{
    finish();
}


void Thread::process()
{
}
