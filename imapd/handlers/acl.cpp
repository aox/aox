// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "acl.h"

#include "user.h"
#include "query.h"
#include "string.h"
#include "mailbox.h"
#include "stringlist.h"
#include "permissions.h"
#include "transaction.h"


class AclData {
public:
    AclData()
        : state( 0 ), type( Acl::SetAcl ), mailbox( 0 ),
          permissions( 0 ), user( 0 ), q( 0 ), t( 0 )
    {}

    int state;
    Acl::Type type;

    String mbox;
    String authid;
    String rights;
    String username;

    Mailbox * mailbox;
    Permissions * permissions;
    User * user;
    Query * q;
    Transaction * t;
};


/*! \class Acl acl.h
    Implements the SETACL/DELETEACL/GETACL/LISTRIGHTS/MYRIGHTS commands
    from RFC 2086.
*/


/*! Creates a new ACL handler. */

Acl::Acl( Type t )
    : d( new AclData )
{
    d->type = t;
}


void Acl::parse()
{
    space();
    d->mbox = astring();

    if ( d->type == SetAcl || d->type == DeleteAcl ||
         d->type == ListRights )
    {
        space();
        d->authid = astring();
    }

    if ( d->type == SetAcl ) {
        space();
        d->rights = astring();
    }

    end();
}


void Acl::execute()
{
    if ( d->state == 0 ) {
        d->mailbox = Mailbox::find( imap()->mailboxName( d->mbox ) );
        if ( !d->mailbox || d->mailbox->synthetic() ||
             d->mailbox->deleted() )
        {
            error( No, d->mbox + " does not exist" );
            finish();
            return;
        }

        if ( !( d->type == MyRights || d->type == GetAcl ) ) {
            d->user = new User;
            d->user->setLogin( d->authid );
            d->user->refresh( this );
        }

        d->permissions = new Permissions( d->mailbox, imap()->user(), this );
        d->state = 1;
    }

    if ( d->state == 1 ) {
        if ( !d->permissions->ready() )
            return;
        if ( d->user && d->user->state() == User::Unverified )
            return;

        if ( d->type == MyRights ) {
            respond( "MYRIGHTS " + d->mbox + " " + d->permissions->string() );
            finish();
            return;
        }

        d->state = 2;
    }

    if ( d->state == 2 ) {
        if ( !d->permissions->allowed( Permissions::Admin ) ) {
            error( No, d->mbox + " is not accessible" );
            finish();
            return;
        }

        if ( d->type == ListRights ) {
            String s( "LISTRIGHTS " + d->mbox + " " );
            if ( d->user->id() == d->mailbox->owner() ) {
                s.append( Permissions::all() );
            }
            else {
                StringList l;

                // We always assign Lookup rights.
                l.append( new String( "l" ) );

                // And we could assign anything else.
                uint i = 0;
                while ( i < Permissions::NumRights ) {
                    String * s = new String;
                    Permissions::Right r = (Permissions::Right)i;
                    if ( r != Permissions::Lookup ) {
                        s->append( Permissions::rightChar( r ) );
                        l.append( s );
                    }
                    i++;
                }

                s.append( l.join( " " ) );
            }
            respond( s );
            finish();
            return;
        }
        else if ( d->type == DeleteAcl ) {
            d->q = new Query( "delete from permissions where "
                              "mailbox=$1 and identifier=$2", this );
            d->q->bind( 1, d->mailbox->id() );
            d->q->bind( 2, d->authid );
            d->q->execute();
        }
        else if ( d->type == GetAcl ) {
            String s;

            if ( d->mailbox->owner() != 0 ) {
                s.append( "select (select login from users where id=$2) "
                          "as identifier, $3::text as rights "
                          "union select identifier,rights from "
                          "permissions where mailbox=$1" );
                d->q = new Query( s, this );
                d->q->bind( 1, d->mailbox->id() );
                d->q->bind( 2, d->mailbox->owner() );
                d->q->bind( 3, Permissions::all() );
            }
            else {
                s.append( "select * from permissions where mailbox=$1" );
                d->q = new Query( s, this );
                d->q->bind( 1, d->mailbox->id() );
            }

            d->q->execute();
        }
        else if ( d->type == SetAcl ) {
            d->t = new Transaction( this );
            d->q = new Query( "lock permissions in exclusive mode", this );
            d->t->enqueue( d->q );
            d->q = new Query( "select * from permissions where "
                              "mailbox=$1 and identifier=$2", this );
            d->q->bind( 1, d->mailbox->id() );
            d->q->bind( 2, d->authid );
            d->t->enqueue( d->q );
            d->t->execute();
        }

        d->state = 3;
    }

    if ( d->state == 3 ) {
        if ( !d->q->done() )
            return;

        if ( d->type == GetAcl ) {
            StringList l;
            while ( d->q->hasResults() ) {
                String * s = new String;
                Row * r = d->q->nextRow();
                s->append( r->getString( "identifier" ) );
                s->append( " " );
                s->append( r->getString( "rights" ) );
                l.append( s );
            }
            respond( "ACL " + d->mbox + " " + l.join( " " ) );
        }
        else if ( d->type == SetAcl ) {
            if ( !d->q->done() )
                return;

            if ( d->q->hasResults() ) {
                d->q = new Query( "update permissions set rights=$3 where "
                                  "mailbox=$1 and identifier=$2", this );
                d->q->bind( 1, d->mailbox->id() );
                d->q->bind( 2, d->authid );
                d->q->bind( 3, d->rights );
            }
            else {
                d->q = new Query( "insert into permissions "
                                  "(mailbox,identifier,rights) "
                                  "values ($1,$2,$3)", this );
                d->q->bind( 1, d->mailbox->id() );
                d->q->bind( 2, d->authid );
                d->q->bind( 3, d->rights );
            }

            d->t->enqueue( d->q );
            d->state = 4;
            d->t->commit();
        }
    }

    if ( d->state == 4 ) {
        if ( !d->t->done() )
            return;
        if ( d->t->failed() )
            error( No, d->t->error() );
    }

    finish();
}
