#include "user.h"

#include "string.h"
#include "event.h"
#include "query.h"
#include "transaction.h"


static Transaction *t;


/*! \class User
    This class represents a Mailstore user.

    It exists only to allow mailstore(1) to create users for the moment.
    It will probably allow list/edit operations in the future.
*/


/*! This function initiates the database operations required to create a
    user named \a login with password \a secret. It returns a pointer to
    a Query object whose state reflects the progress of the operation.
    It notifies \a ev of completion.
*/

Query *User::create( const String &login, const String &secret,
                     EventHandler *ev )
{
    class UserCreator : public EventHandler {
    private:
        Query *q;
    public:
        UserCreator( Query *status ) : q( status ) {}

        void execute() {
            if ( t->done() ) {
                q->setState( Query::Completed );
                if ( t->failed() )
                    q->setError( t->error() );
                q->notify();
            }
        }
    };

    Query *q = new Query( ev );
    t = new Transaction( new UserCreator( q ) );

    Query *createUser =
        new Query( "insert into users (login, secret) values ($1, $2)", 0 );
    createUser->bind( 1, login );
    createUser->bind( 2, secret );
    t->enqueue( createUser );

    Query *createInbox =
        new Query( "insert into mailboxes (name) values ($1)", 0 );
    createInbox->bind( 1, "/users/" + login + "/INBOX" );
    t->enqueue( createInbox );

    t->commit();
    return q;
}
