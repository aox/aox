// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "reset.h"

#include "imap.h"
#include "user.h"
#include "query.h"
#include "mailbox.h"


class XOryxResetData
    : public Garbage
{
public:
    XOryxResetData(): messages( 0 ), mailboxes( 0 ) {}

    Query * messages;
    Query * mailboxes;
};

/*! \class XOryxReset reset.h

    Deletes all messages in the authenticated user's inbox and sets
    UIDNEXT and 1. Perhaps it should also delete all unused flag
    names.
*/


void XOryxReset::execute()
{
    if ( !d ) {
        d = new XOryxResetData;

        Mailbox * inbox = imap()->user()->inbox();

        d->messages = new Query( "delete from messages where mailbox=$1",
                                 this );
        d->messages->bind( 1, inbox->id() );
        d->messages->execute();

        d->mailboxes = new Query( "update mailboxes set uidnext=1 where id=$1",
                                this );
        d->mailboxes->bind( 1, inbox->id() );
        d->mailboxes->execute();

        inbox->setUidnext( 1 );
        inbox->clear();
    }

    if ( d->messages->done() && d->mailboxes->done() )
        finish();
}
