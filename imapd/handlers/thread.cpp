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
    end();
}


void Thread::execute()
{
    finish();
}
