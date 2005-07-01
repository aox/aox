// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MAILBOXVIEW_H
#define MAILBOXVIEW_H

#include "session.h"

#include "list.h"


class MailboxView: public Session
{
public:
    MailboxView( Mailbox * );

    class Thread
    {
    private:
        struct M {
            M( uint u, Message * m ): uid( u ), message( m ) {}

            uint uid;
            Message * message;
        };
        List<M> m;

        M * member( uint n ) const {
            List<M>::Iterator i( m );
            while ( i && n ) {
                ++i;
                --n;
            }
            return i;
        }

    public:
        Thread() {}

        void append( uint uid, Message * msg ) {
            m.append( new M( uid, msg ) );
        }
        Message * message( uint n ) const {
            M * m = member( n );
            if ( m )
                return m->message;
            return 0;
        }
        uint uid( uint n ) const {
            M * m = member( n );
            if ( m )
                return m->uid;
            return 0;
        }
        uint messages() const {
            return m.count();
        }
    };

    static MailboxView * find( Mailbox * );

    static String baseSubject( const String & );

    Thread * thread( const String & subject );
    Thread * thread( uint );

    List<Thread> * allThreads() const;

    void refresh( EventHandler * owner );
    bool ready();

    void threadMessage( uint, Message * );

private:
    class MailboxViewData * d;
};


#endif
