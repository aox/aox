// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "thread.h"


class ThreadData
    : public Garbage
{
public:
    ThreadData()
        : uid( false )
    {}

    bool uid;
    String mechanism;
    String charset;
};


/*! \class Thread thread.h
    Implements the THREAD extension described in
    draft-ietf-imapext-sort.
*/


/*! Creates a new handler for THREAD (or UID THREAD, if \a u is true).
*/

Thread::Thread( bool u )
    : d( new ThreadData )
{
    d->uid = u;
}


void Thread::parse()
{
    space();
    d->mechanism = atom().lower();
    if ( d->mechanism != "orderedsubject" )
        error( Bad, "Unsupported THREAD mechanism: " + d->mechanism );
    space();
    d->charset = astring();
    end();
}


void Thread::execute()
{
    finish();
}
