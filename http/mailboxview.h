// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MAILBOXVIEW_H
#define MAILBOXVIEW_H

#include "session.h"

#include "list.h"
#include "message.h"


class MailboxView: public Session
{
public:
    MailboxView( Mailbox * );

    class Thread
        : public Garbage
    {
    public:
        List<Message> m;

        Thread() {}

        Message * message( uint n ) const {
            List<Message>::Iterator i( m );
            while ( i && n ) {
                ++i;
                --n;
            }
            return i;
        }

        uint uid( uint n ) const {
            Message * m = message( n );
            if ( m )
                return m->uid();
            return 0;
        }

        uint messages() const {
            return m.count();
        }
    };

    static MailboxView * find( Mailbox * );

    Thread * thread( const String & subject );
    Thread * thread( uint );

    List<Thread> * allThreads() const;

    void refresh( EventHandler * owner );
    bool ready();

    void threadMessage( Message * );

private:
    class MailboxViewData * d;
};


#endif
