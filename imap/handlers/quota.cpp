// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "quota.h"

#include "mailbox.h"
#include "query.h"
#include "user.h"


/*! \class GetQuota quota.h

    The GetQuota command implements the GETQUOTA command defined by
    RFC 2087. It is the only part Archiveopteryx really implements; we
    want to report usage, not impose quotas.

    Usage is defined as the sum of RFC822-format size, in kb. This is
    usually much bigger than the actual number of kilobytes used by
    the database for storing the mail (at one site by a factor of
    four), but it'll do for reporting usage.
*/

void GetQuota::parse()
{
    space();
    EString x = astring();
    end();
    if ( !x.isEmpty() )
        error( No, "No such quota root: " + x.quoted() );
}


void GetQuota::execute()
{
    if ( !q ) {
        q = new Query( "select count(*) as c,"
                       " sum(rfc822size::bigint)::bigint / 1024 as s "
                       "from "
                       "(select distinct on (m.id) rfc822size from messages m"
                       " join mailbox_messages mm on (m.id=mm.message)"
                       " join mailboxes mb on (mm.mailbox=mb.id)"
                       " where mb.owner=$1) hellothere", this );
        q->bind( 1, imap()->user()->id() );
        q->execute();
    }

    if ( !q->done() )
        return;

    if ( q->failed() ) {
        error( No, "Database problem: " + q->error() );
        return;
    }

    EString quota = fn( imap()->user()->quota() );
    Row * r = q->nextRow();
    if ( r )
        respond( "QUOTA \"\" ("
                 "STORAGE " + fn( r->getBigint( "s" ) ) + " " + quota + " "
                 "MESSAGE " + fn( r->getBigint( "c" ) ) + "  " + quota + ")" );
    finish();
}


/*! \class SetQuota quota.h

    We don't allow setting quotas within IMAP, so this class is a no-op.
*/

void SetQuota::parse()
{
    error( No, "Not supported via IMAP" );
}


/*! Does nothing, but has to be there. */

void SetQuota::execute()
{
}


/*! \class GetQuotaRoot quota.h

    The GetQuota command implements the GETQUOTAROOT command defined by
    RFC 2087, a slightly fancier version of GETQUOTA.
*/


/*! Reports on the quota for a specified mailbox. */

void GetQuotaRoot::parse()
{
    space();
    m = mailbox();
    end();
}


void GetQuotaRoot::execute()
{
    if ( !m )
        return;

    if ( !x ) {
        if ( m->owner() == imap()->user()->id() ) {
            respond( "QUOTAROOT " + imapQuoted( m ) + " \"\"" );
        }
        else {
            finish();
            return;
        }
        x = true;
    }

    GetQuota::execute();
}


/*! \class SetQuotaRoot quota.h

    We don't allow setting quotas via IMAP, so this handler just
    returns an error.
*/

void SetQuotaRoot::parse()
{
    error( No, "Not supported via IMAP" );
}


/*! Does nothing, but has to be there. */

void SetQuotaRoot::execute()
{
}
