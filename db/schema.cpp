// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "schema.h"

#include "log.h"
#include "query.h"
#include "transaction.h"
#include "stringlist.h"
#include "allocator.h"
#include "dict.h"
#include "md5.h"


int currentRevision = 27;


class SchemaData
    : public Garbage
{
public:
    SchemaData()
        : l( new Log( Log::Database ) ),
          state( 0 ), substate( 0 ), revision( 0 ),
          lock( 0 ), seq( 0 ), update( 0 ), q( 0 ), t( 0 ),
          result( 0 ), upgrade( false ), commit( true )
    {}

    Log *l;
    int state;
    int substate;
    int revision;
    Query *lock, *seq, *update, *q;
    Transaction *t;
    Query *result;
    bool upgrade;
    bool commit;
    String version;
};


/*! \class Schema schema.h
    This class represents the Oryx database schema.

    The static checkRevision() function verifies during server startup
    that the running server is compatible with the existing schema.

    The static checkAccess() function verifies during server startup
    that the running server does not have privileged access to the
    database.
*/


/*! Creates a new Schema object to check that the existing schema is one
    that the running server understands. If \a upgrade is true (which it
    is not, by default) and the schema is too old, it will be upgraded.
    (If \a upgrade is false, a "please upgrade" message will be issued.)

    If \a commit is false (which it also is not, by default), the SQL
    statements performed during the upgrade will not be COMMITted, but
    their success or failure will be reported.

    The \a owner will be notified of progress via the Query returned by
    result().
*/

Schema::Schema( EventHandler * owner, bool upgrade, bool commit )
    : d( new SchemaData )
{
    d->result = new Query( owner );
    d->upgrade = upgrade;
    d->commit = commit;
    d->t = new Transaction( this );
}


/*! Returns a Query object that can be used to track the progress of the
    Schema verification or upgradation. The Query's owner is set by the
    constructor when the Schema is created.
*/

Query * Schema::result() const
{
    return d->result;
}


/*! This function is responsible for checking that the running server is
    compatible with the existing database schema, and to notify \a owner
    when the verification is complete.

    If the schema is not compatible, a disaster is logged.

    The function expects to be called from ::main(), and should be the
    first database transaction.
*/

void Schema::checkRevision( EventHandler * owner )
{
    Schema * s = new Schema( owner );
    owner->waitFor( s->result() );
    s->execute();
}


/*! After execute() has completed, this function returns the version
    ("8.1.3") of the running Postgres server.
*/

String Schema::serverVersion() const
{
    return d->version;
}


/*! Checks or upgrades the schema as required. */

void Schema::execute()
{
    if ( d->state == 0 ) {
        d->lock =
            new Query( "select version() as version, revision from "
                       "mailstore for update", this );
        d->t->enqueue( d->lock );
        d->t->execute();
        d->state = 1;
    }

    if ( d->state == 1 ) {
        if ( !d->lock->done() )
            return;

        Row *r = d->lock->nextRow();
        if ( r ) {
            d->version
                = r->getString( "version" ).simplified().section( " ", 2 );
            d->revision = r->getInt( "revision" );
        }

        if ( !r || d->lock->failed() ) {
            fail( "Bad database: Couldn't query the mailstore table.",
                  d->lock );
            d->revision = ::currentRevision;
            d->t->commit();
            d->state = 5;
        }
        else if ( d->revision == ::currentRevision ) {
            d->result->setState( Query::Completed );
            d->t->commit();
            d->state = 5;
        }
        else if ( d->upgrade && d->revision < ::currentRevision ) {
            d->l->log( "Updating schema from revision " +
                       fn( d->revision ) + " to revision " +
                       fn( ::currentRevision ) );
            d->state = 2;
        }
        else {
            String s( "The existing schema (revision #" );
            s.append( fn( d->revision ) );
            s.append( ") is " );
            if ( d->revision < ::currentRevision )
                s.append( "older" );
            else
                s.append( "newer" );
            s.append( " than this server (version " );
            s.append( Configuration::compiledIn( Configuration::Version ) );
            s.append( ") expected (revision #" );
            s.append( fn( ::currentRevision ) );
            s.append( "). Please " );
            if ( d->revision < ::currentRevision )
                s.append( "run 'aox upgrade schema'" );
            else
                s.append( "upgrade" );
            s.append( " or contact support." );
            fail( s );
            d->revision = ::currentRevision;
            d->t->commit();
            d->state = 5;
        }
    }

    while ( d->revision < ::currentRevision ) {
        if ( d->state == 2 ) {
            if ( !singleStep() )
                return;
            d->state = 3;
        }

        if ( d->state == 3 ) {
            d->update =
                new Query( "update mailstore set revision=revision+1",
                           this );
            d->t->enqueue( d->update );
            d->t->execute();
            d->state = 4;
        }

        if ( d->state == 4 ) {
            if ( !d->update->done() )
                return;

            d->state = 2;
            d->revision++;

            if ( d->revision == ::currentRevision ) {
                if ( d->commit )
                    d->t->commit();
                else
                    d->t->rollback();
                d->state = 6;
                break;
            }
        }
    }

    if ( d->state == 5 || d->state == 6 ) {
        if ( !d->t->done() )
            return;

        if ( d->t->failed() && !d->result->failed() ) {
            String s;
            if ( d->upgrade )
                s = "The schema could not be upgraded to revision " +
                    fn( ::currentRevision );
            else
                s = "The schema could not be validated.";
            fail( s, d->t->failedQuery() );
        }
        else if ( d->state == 6 ) {
            d->result->setState( Query::Completed );
            d->l->log( "Schema updated to revision " +
                       fn( ::currentRevision ) );
        }
        d->state = 7;
    }

    if ( d->state == 7 ) {
        d->state = 42;
        d->result->notify();
    }
}


/*! Uses a helper function to upgrade the schema from d->revision to
    d->revision+1. Returns false if the helper has not yet completed
    its work.
*/

bool Schema::singleStep()
{
    bool c;

    switch ( d->revision ) {
    case 1:
        c = stepTo2(); break;
    case 2:
        c = stepTo3(); break;
    case 3:
        c = stepTo4(); break;
    case 4:
        c = stepTo5(); break;
    case 5:
        c = stepTo6(); break;
    case 6:
        c = stepTo7(); break;
    case 7:
        c = stepTo8(); break;
    case 8:
        c = stepTo9(); break;
    case 9:
        c = stepTo10(); break;
    case 10:
        c = stepTo11(); break;
    case 11:
        c = stepTo12(); break;
    case 12:
        c = stepTo13(); break;
    case 13:
        c = stepTo14(); break;
    case 14:
        c = stepTo15(); break;
    case 15:
        c = stepTo16(); break;
    case 16:
        c = stepTo17(); break;
    case 17:
        c = stepTo18(); break;
    case 18:
        c = stepTo19(); break;
    case 19:
        c = stepTo20(); break;
    case 20:
        c = stepTo21(); break;
    case 21:
        c = stepTo22(); break;
    case 22:
        c = stepTo23(); break;
    case 23:
        c = stepTo24(); break;
    case 24:
        c = stepTo25(); break;
    case 25:
        c = stepTo26(); break;
    }

    return c;
}


/*! Changes the type of users.login and users.secret to text to remove
    the made-up length restriction on the earlier varchar field.
*/

bool Schema::stepTo2()
{
    if ( d->substate == 0 ) {
        d->l->log( "Changing users.login/secret to text", Log::Debug );
        d->q = new Query( "alter table users add login2 text", this );
        d->t->enqueue( d->q );
        d->q = new Query( "update users set login2=login", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table users drop login", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table users rename login2 to login",
                       this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table users add unique(login)",
                       this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table users add secret2 text", this );
        d->t->enqueue( d->q );
        d->q = new Query( "update users set secret2=secret", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table users drop secret", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table users rename secret2 to secret",
                       this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Merges the binary_parts table into bodyparts. */

bool Schema::stepTo3()
{
    if ( d->substate == 0 ) {
        d->l->log( "Merging bodyparts and binary_parts", Log::Debug );
        d->q = new Query( "alter table bodyparts add hash text", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table bodyparts add data bytea", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table bodyparts add text2 text", this );
        d->t->enqueue( d->q );
        d->q = new Query( "update bodyparts set data=b.data from "
                          "binary_parts b where id=b.bodypart", this );
        d->t->enqueue( d->q );
        d->q = new Query( "declare parts cursor for "
                          "select id,text,data from bodyparts", this );
        d->t->enqueue( d->q );
        d->q = new Query( "fetch 512 from parts", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        while ( d->q->hasResults() ) {
            Row *r = d->q->nextRow();
            String text, data;

            Query *u =
                new Query( "update bodyparts set "
                           "text2=$1,hash=$2 where id=$3", this );
            if ( r->isNull( "text" ) ) {
                data = r->getString( "data" );
                u->bindNull( 1 );
                u->bind( 2, MD5::hash( data ).hex() );
            }
            else {
                text = r->getString( "text" );
                u->bind( 1, text );
                u->bind( 2, MD5::hash( text ).hex() );
            }
            u->bind( 3, r->getInt( "id" ) );
            d->t->enqueue( u );
        }

        if ( !d->q->done() )
            return false;

        if ( d->q->rows() != 0 ) {
            d->q = new Query( "fetch 512 from parts", this );
            d->t->enqueue( d->q );
            d->t->execute();
            return false;
        }
        else {
            d->substate = 2;
            d->t->enqueue( new Query( "close parts", this ) );
        }
    }

    if ( d->substate == 2 ) {
        d->q = new Query( "alter table bodyparts drop text", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table bodyparts rename text2 to text", this );
        d->t->enqueue( d->q );
        d->q = new Query( "select id,hash from bodyparts where hash in "
                          "(select hash from bodyparts group by hash"
                          " having count(*) > 1)", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 3;
    }

    if ( d->substate == 3 ) {
        if ( !d->q->done() )
            return false;

        StringList ids;
        Dict< uint > hashes;

        while ( d->q->hasResults() ) {
            Row *r = d->q->nextRow();
            uint id = r->getInt( "id" );
            String hash = r->getString( "hash" );

            uint *old = hashes.find( hash );
            if ( old ) {
                ids.append( fn( id ) );
                Query *u =
                    new Query( "update part_numbers set "
                               "bodypart=$1 where bodypart=$2", this );
                u->bind( 1, *old );
                u->bind( 2, id );
                d->t->enqueue( u );
            }
            else {
                uint * tmp
                    = (uint*)Allocator::alloc( sizeof(uint), 0 );
                *tmp = id;
                hashes.insert( hash, tmp );
            }
        }

        if ( !ids.isEmpty() ) {
            d->q = new Query( "delete from bodyparts where id in "
                              "(" + ids.join(",") + ")", this );
            d->t->enqueue( d->q );
        }
        d->q = new Query( "drop table binary_parts", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table bodyparts add unique(hash)", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 4;
    }

    if ( d->substate == 4 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Move message flags from the messages table to the extra_flags table,
    now renamed just "flags".
*/

bool Schema::stepTo4()
{
    if ( d->substate == 0 ) {
        d->l->log( "Creating flags from messages/extra_flags.", Log::Debug );
        d->q = new Query( "alter table extra_flags rename to flags", this );
        d->t->enqueue( d->q );
        d->q = new Query( "insert into flag_names (name) values ($1)", this );
        d->q->bind( 1, "\\Deleted" );
        d->t->enqueue( d->q );
        d->q = new Query( "insert into flag_names (name) values ($1)", this );
        d->q->bind( 1, "\\Answered" );
        d->t->enqueue( d->q );
        d->q = new Query( "insert into flag_names (name) values ($1)", this );
        d->q->bind( 1, "\\Flagged" );
        d->t->enqueue( d->q );
        d->q = new Query( "insert into flag_names (name) values ($1)", this );
        d->q->bind( 1, "\\Draft" );
        d->t->enqueue( d->q );
        d->q = new Query( "insert into flag_names (name) values ($1)", this );
        d->q->bind( 1, "\\Seen" );
        d->t->enqueue( d->q );
        d->q = new Query( "insert into flags (mailbox,uid,flag) "
                          "select mailbox,uid,"
                          "(select id from flag_names"
                          " where name='\\Deleted') from messages "
                          "where deleted", this );
        d->t->enqueue( d->q );
        d->q = new Query( "insert into flags (mailbox,uid,flag) "
                          "select mailbox,uid,"
                          "(select id from flag_names"
                          " where name='\\Answered') from messages "
                          "where answered", this );
        d->t->enqueue( d->q );
        d->q = new Query( "insert into flags (mailbox,uid,flag) "
                          "select mailbox,uid,"
                          "(select id from flag_names"
                          " where name='\\Flagged') from messages "
                          "where flagged", this );
        d->t->enqueue( d->q );
        d->q = new Query( "insert into flags (mailbox,uid,flag) "
                          "select mailbox,uid,"
                          "(select id from flag_names"
                          " where name='\\Draft') from messages "
                          "where draft", this );
        d->t->enqueue( d->q );
        d->q = new Query( "insert into flags (mailbox,uid,flag) "
                          "select mailbox,uid,"
                          "(select id from flag_names"
                          " where name='\\Seen') from messages "
                          "where seen", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table messages drop deleted", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table messages drop answered", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table messages drop flagged", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table messages drop draft", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table messages drop seen", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Add some indices on header_fields, address_fields, and flags. */

bool Schema::stepTo5()
{
    if ( d->substate == 0 ) {
        d->l->log( "Adding hf_mup, af_mu, fl_mu indices.", Log::Debug );
        d->q = new Query( "create index hf_mup on "
                          "header_fields (mailbox,uid,part)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "create index af_mu on "
                          "address_fields (mailbox,uid)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "create index fl_mu on flags (mailbox,uid)",
                          this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Move bodyparts.bytes/lines to the part_numbers table. */

bool Schema::stepTo6()
{
    if ( d->substate == 0 ) {
        d->l->log( "Moving bytes/lines to part_numbers.", Log::Debug );
        d->q = new Query( "alter table part_numbers add bytes integer",
                          this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table part_numbers add lines integer",
                          this );
        d->t->enqueue( d->q );
        d->q = new Query( "update part_numbers set bytes=bodyparts.bytes,"
                          "lines=bodyparts.lines from bodyparts where "
                          "part_numbers.bodypart=bodyparts.id", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table part_numbers alter bodypart "
                          "drop not null", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table bodyparts drop lines", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Add header_fields.position. */

bool Schema::stepTo7()
{
    if ( d->substate == 0 ) {
        d->l->log( "Adding header_fields.position.", Log::Debug );
        d->q = new Query( "alter table header_fields add "
                          "position integer", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table header_fields alter part "
                          "set not null", this );
        d->t->enqueue( d->q );
        d->q = new Query( "create temporary sequence hf_pos", this );
        d->t->enqueue( d->q );
        d->q = new Query( "declare groups cursor for "
                          "select distinct mailbox,uid,part "
                          "from header_fields", this );
        d->t->enqueue( d->q );
        d->q = new Query( "fetch 512 from groups", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        while ( d->q->hasResults() ) {
            Row *r = d->q->nextRow();

            Query *u =
                new Query( "update header_fields set position="
                           "nextval('hf_pos') where id in "
                           "(select id from header_fields "
                           "where not (mailbox,uid,part) is "
                           "distinct from ($1,$2,$3) order by id)",
                           this );
            u->bind( 1, r->getInt( "mailbox" ) );
            u->bind( 2, r->getInt( "uid" ) );
            u->bind( 3, r->getString( "part" ) );
            d->t->enqueue( u );

            u = new Query( "alter sequence hf_pos restart with 1", this );
            d->t->enqueue( u );
        }

        if ( !d->q->done() )
            return false;

        if ( d->q->rows() != 0 ) {
            d->q = new Query( "fetch 512 from groups", this );
            d->t->enqueue( d->q );
            d->t->execute();
            return false;
        }
        else {
            d->t->enqueue( new Query( "close groups", this ) );
            d->q = new Query( "alter table header_fields add unique "
                              "(mailbox,uid,part,position,field)", this );
            d->t->enqueue( d->q );
            d->t->execute();
            d->substate = 2;
        }
    }

    if ( d->substate == 2 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Make address_fields refer to header_fields. */

bool Schema::stepTo8()
{
    if ( d->substate == 0 ) {
        d->l->log( "Making address_fields refer to header_fields.",
                Log::Debug );
        d->q = new Query( "delete from address_fields", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table address_fields drop field", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table address_fields add part text", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table address_fields alter part "
                          "set not null", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table address_fields add "
                          "position integer", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table address_fields alter "
                          "position set not null", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table address_fields add "
                          "field integer", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table address_fields alter field "
                          "set not null", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table address_fields add foreign key "
                          "(mailbox,uid,part,position,field) "
                          "references header_fields "
                          "(mailbox,uid,part,position,field) "
                          "on delete cascade", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Remove the recent_messages table altogether. */

bool Schema::stepTo9()
{
    if ( d->substate == 0 ) {
        d->l->log( "Removing recent_messages.", Log::Debug );
        d->q = new Query( "alter table mailboxes add "
                          "first_recent integer ", this );
        d->t->enqueue( d->q );
        d->q = new Query( "update mailboxes set "
                          "first_recent=coalesce((select min(uid) "
                          "from recent_messages where "
                          "mailbox=mailboxes.id),uidnext)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table mailboxes alter first_recent "
                          "set not null", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table mailboxes alter first_recent "
                          "set default 1", this );
        d->t->enqueue( d->q );
        d->q = new Query( "drop table recent_messages", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Add "on delete cascade" to the mailboxes.owner reference. */

bool Schema::stepTo10()
{
    if ( d->substate == 0 ) {
        d->l->log( "Altering mailboxes_owner_fkey.", Log::Debug );

        String constraint = "mailboxes_owner_fkey";
        if ( d->version.startsWith( "7" ) )
            constraint = "$1";

        d->q = new Query( "alter table mailboxes drop constraint "
                          "\"" + constraint + "\"", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table mailboxes add constraint "
                          "mailboxes_owner_fkey foreign key "
                          "(owner) references users(id) "
                          "on delete cascade", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Delete the revisions sequence. */

bool Schema::stepTo11()
{
    if ( d->substate == 0 ) {
        d->l->log( "Deleting revisions.", Log::Debug );
        d->q = new Query( "drop sequence revisions", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Reverse stepTo10(). We don't want to delete rows in mailboxes. */

bool Schema::stepTo12()
{
    if ( d->substate == 0 ) {
        d->l->log( "Reverting mailboxes_owner_fkey change.", Log::Debug );
        d->q = new Query( "alter table mailboxes drop constraint "
                          "\"mailboxes_owner_fkey\"", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table mailboxes add constraint "
                          "mailboxes_owner_fkey foreign key "
                          "(owner) references users(id)", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Create the annotation_names and annotations tables. */

bool Schema::stepTo13()
{
    if ( d->substate == 0 ) {
        d->l->log( "Creating annotations/annotation_names.", Log::Debug );
        d->q = new Query( "create table annotation_names"
                          "(id serial primary key, name text unique)",
                          this );
        d->t->enqueue( d->q );
        d->q = new Query( "create table annotations"
                          "(mailbox integer not null,uid integer not null,"
                          "owner integer references users(id),name integer "
                          "not null references annotation_names(id),"
                          "value text,type text,language text,"
                          "displayname text,"
                          "unique(mailbox,uid,owner,name),"
                          "foreign key (mailbox,uid) references "
                          "messages(mailbox,uid) on delete cascade)",
                          this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Add the tables required to support views. */

bool Schema::stepTo14()
{
    if ( d->substate == 0 ) {
        d->l->log( "Creating views/view_messages.", Log::Debug );
        d->q = new Query( "create table views ("
                          "id serial primary key,"
                          "source integer not null references mailboxes(id) "
                          "on delete cascade,"
                          "view integer not null references mailboxes(id) "
                          "on delete cascade unique,"
                          "suidnext integer not null,"
                          "selector text)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "create table view_messages ("
                          "view integer not null references views(view) "
                          "on delete cascade,"
                          "uid integer not null,"
                          "source integer not null,"
                          "suid integer not null,"
                          "foreign key (source, suid) "
                          "references messages(mailbox, uid) "
                          "on delete cascade)", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Add "on delete cascade" to the subscriptions/annotations.owner
    references.
*/

bool Schema::stepTo15()
{
    if ( d->substate == 0 ) {
        d->l->log( "Altering subscriptions_owner_fkey.", Log::Debug );

        String ca( "subscriptions_owner_fkey" );
        String cb( "annotations_owner_fkey" );
        if ( d->version.startsWith( "7" ) ) {
            ca = "$1";
            cb = "$1";
        }

        d->q = new Query( "alter table subscriptions drop constraint "
                          "\"" + ca + "\"", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table subscriptions add constraint "
                          "subscriptions_owner_fkey foreign key "
                          "(owner) references users(id) "
                          "on delete cascade", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table annotations drop constraint "
                          "\"" + cb + "\"", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table annotations add constraint "
                          "annotations_owner_fkey foreign key "
                          "(owner) references users(id) "
                          "on delete cascade", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Add the aliases table. */

bool Schema::stepTo16()
{
    if ( d->substate == 0 ) {
        d->l->log( "Creating aliases table.", Log::Debug );
        d->q = new Query( "create table aliases (address text,mailbox "
                          "integer not null references mailboxes(id))",
                          this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Drop the aliases table from #16 (never released) and recreate it,
    with a reference to the address, and a link from users.
*/

bool Schema::stepTo17()
{
    if ( d->substate == 0 ) {
        d->l->log( "Recreating unified aliases table.", Log::Debug );
        d->q = new Query( "drop table aliases", this );
        d->t->enqueue( d->q );
        d->q = new Query( "create table aliases (id serial primary key, "
                          "address integer not null unique references "
                          "addresses(id), mailbox integer not null "
                          "references mailboxes(id))", this );
        d->t->enqueue( d->q );
        d->q = new Query( "insert into aliases (address, mailbox) "
                          "select address,inbox from users", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table users add alias integer "
                          "references aliases(id)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "update users set alias=(select id from aliases "
                          "where aliases.address=users.address and "
                          "mailbox=inbox)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table users alter alias set not null", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table users drop address", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table users drop inbox", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Add the scripts table. */

bool Schema::stepTo18()
{
    if ( d->substate == 0 ) {
        d->l->log( "Creating scripts table.", Log::Debug );
        d->q = new Query( "create table scripts (id serial primary key,"
                          "owner integer not null references users(id),"
                          "name text, active boolean not null default 'f',"
                          "script text)", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Add the date_fields table. */

bool Schema::stepTo19()
{
    if ( d->substate == 0 ) {
        d->l->log( "Creating date_fields table.", Log::Debug );
        d->q = new Query( "create table date_fields (mailbox "
                          "integer not null, uid integer not null, "
                          "value timestamp with time zone, "
                          "foreign key (mailbox,uid) references "
                          "messages(mailbox,uid) on delete cascade )",
                          this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Populate the date_fields table from header_fields. */

bool Schema::stepTo20()
{
    if ( d->substate == 0 ) {
        d->l->log( "Populating the date_fields table.", Log::Debug );
        d->q =
            new Query( "select count(substring(value from '^[^(]*')::timestamp "
                       "with time zone) from header_fields where field=(select "
                       "id from field_names where name='Date') and "
                       "substring(substring(value from "
                       "'[+-][0-9][0-9][0-9][0-9]') from 2)::integer < 1400",
                       this );
        d->q->allowFailure();
        d->q->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;

        if ( d->q->failed() ) {
            d->l->log( "Not attempted due to unparseable dates.",
                       Log::Debug );
            d->substate = 0;
            return true;
        }

        d->q = new Query( "delete from date_fields", this );
        d->t->enqueue( d->q );
        d->q = new Query( "insert into date_fields select "
                          "mailbox, uid, substring(value from "
                          "'^[^(]*')::timestamp with time zone from "
                          "header_fields where field=(select id from "
                          "field_names where name='Date') and "
                          "substring(substring(value from "
                          "'[+-][0-9][0-9][0-9][0-9]') from 2)::integer < "
                          "1400", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 2;
    }

    if ( d->substate == 2 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Remove unnecessary stuff from annotations. */

bool Schema::stepTo21()
{
    if ( d->substate == 0 ) {
        d->l->log( "Removing fields from annotations table.", Log::Debug );
        d->q = new Query( "alter table annotations drop type", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table annotations drop language", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table annotations drop displayname", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! For any two flag names that differ only in case, moves all flags
    from one to the other and removes the unused one.  Then adds an
    index to ensure uniqueness in the future.
*/

bool Schema::stepTo22()
{
    if ( d->substate == 0 ) {
        d->l->log( "Finding flag names that differ only in case.", Log::Debug );
        d->q = new Query( "select a.id as to, b.id as from, a.name as name "
                          "from flag_names a, flag_names b "
                          "where a.id < b.id and lower(a.name)=lower(b.name) "
                          "order by a.id, b.id", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;

        if ( d->q->failed() ) {
            d->l->log( "Internal error.", Log::Debug );
            d->substate = 0;
            return true;
        }

        d->l->log( "Changing case for " + fn( d->q->rows() ) + " flags.",
                   Log::Debug );

        Row * r;
        while ( (r=d->q->nextRow()) != 0 ) {
            d->l->log( "Unbreaking " + r->getString( "name" ) + ".",
                       Log::Debug );

            Query * q;
            q = new Query( "update flags set flag=$1 where flag=$2", 0 );
            q->bind( 1, r->getInt( "to" ) );
            q->bind( 2, r->getInt( "from" ) );
            d->t->enqueue( q );

            q = new Query( "delete from flag_names where id=$1", 0 );
            q->bind( 1, r->getInt( "from" ) );
            d->t->enqueue( q );
        }
        d->q = new Query( "alter table flag_names drop constraint "
                          "flag_names_name_key", this );
        d->t->enqueue( d->q );
        d->q = new Query( "create unique index fn_uname on "
                          "flag_names (lower(name))", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 2;
    }

    if ( d->substate == 2 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Add the deleted_messages table. */

bool Schema::stepTo23()
{
    if ( d->substate == 0 ) {
        d->l->log( "Creating deleted_messages table.", Log::Debug );
        d->q = new Query( "create table deleted_messages (mailbox "
                          "integer not null, uid integer not null, "
                          "deleted_by integer not null references "
                          "users(id), deleted_at timestamp not null "
                          "default current_timestamp, reason text, "
                          "foreign key (mailbox,uid) references "
                          "messages(mailbox,uid) on delete cascade )",
                          this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Create threads/thread_members if they don't exist already. */

bool Schema::stepTo24()
{
    if ( d->substate == 0 ) {
        d->l->log( "Creating threads/thread_messages if necessary.",
                   Log::Debug );
        d->q = new Query( "select * from information_schema.tables where "
                          "table_name='threads'", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        if ( !d->q->hasResults() ) {
            d->q = new Query( "create table threads (id serial primary "
                              "key,mailbox integer not null references "
                              "mailboxes(id),subject text unique)",
                              this );
            d->t->enqueue( d->q );
            d->q = new Query( "create table thread_members (thread integer "
                              "not null references threads(id),mailbox integer "
                              "not null,uid integer not null,foreign key "
                              "(mailbox,uid) references messages(mailbox,uid) "
                              "on delete cascade)", this );
            d->t->enqueue( d->q );
            d->t->execute();
            d->substate = 2;
        }
        else {
            d->substate = 0;
        }
    }

    if ( d->substate == 2 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Adds the modsequences table. */

bool Schema::stepTo25()
{
    if ( d->substate == 0 ) {
        d->l->log( "Creating modsequences table.", Log::Debug );
        String dbuser( Configuration::text( Configuration::DbUser ) );
        d->q = new Query( "create sequence nextmodsequence", this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,update on nextmodsequence to " +
                          dbuser, this );
        d->t->enqueue( d->q );
        d->q = new Query( "create table modsequences ("
                          "    mailbox     integer not null,"
                          "    uid         integer not null,"
                          "    modseq      bigint not null,"
                          "    foreign key (mailbox, uid)"
                          "                references messages(mailbox, uid)"
                          ")", this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant insert,update on modsequences to " +
                          dbuser, this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
    
}


/*! Alters deleted_messages.deleted_at to be a timestamp with time zone. */

bool Schema::stepTo26()
{
    if ( d->substate == 0 ) {
        d->l->log( "Altering deleted_messages.deleted_at to timestamptz.",
                   Log::Debug );
        d->q = new Query( "alter table deleted_messages add dtz timestamp "
                          "with time zone", this );
        d->t->enqueue( d->q );
        d->q = new Query( "update deleted_messages set dtz=deleted_at", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table deleted_messages alter dtz set "
                          "default current_timestamp", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table deleted_messages alter dtz set "
                          "not null", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table deleted_messages drop deleted_at",
                          this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table deleted_messages rename dtz to "
                          "deleted_at", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Add "on delete cascade" to the mailboxes.owner reference. */

bool Schema::stepTo27()
{
    if ( d->substate == 0 ) {
        d->l->log( "Altering modsequences_mailbox_fkey.", Log::Debug );

        String constraint = "modsequences_mailbox_fkey";
        if ( d->version.startsWith( "7" ) )
            constraint = "$1";

        d->q = new Query( "alter table modsequences drop constraint "
                          "\"" + constraint + "\"", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table modsequences add constraint "
                          "modsequences_mailbox_fkey foreign key "
                          "(mailbox,uid) references "
                          "messages(mailbox,uid) "
                          "on delete cascade", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        d->l->log( "Done.", Log::Debug );
        d->substate = 0;
    }

    return true;
}


/*! Given an error message \a s and, optionally, the query \a q that
    caused the error, this private helper function logs a suitable set
    of Disaster messages (including the Query::description()) and sets
    the error message for d->result to \a s.
*/

void Schema::fail( const String &s, Query * q )
{
    d->result->setError( s );
    d->l->log( s, Log::Disaster );
    if ( q ) {
        d->l->log( "Query: " + q->description(), Log::Disaster );
        d->l->log( "Error: " + q->error(), Log::Disaster );
    }
}


/*! This static function returns the schema revision current at the time
    this server was compiled.
*/

int Schema::currentRevision()
{
    return ::currentRevision;
}


/*! This function checks that the server doesn't have privileged access
    to the database. It notifies \a owner when the check is complete. A
    disaster is logged if the server is connected to the database as an
    unduly privileged user.

    The function expects to be called from ::main() after
    Schema::checkRevision().
*/

void Schema::checkAccess( EventHandler * owner )
{
    class AccessChecker
        : public EventHandler
    {
    public:
        Log * l;
        Query * q;
        Query * result;

        AccessChecker( EventHandler * owner )
            : l( new Log( Log::Database ) ), q( 0 ), result( 0 )
        {
            result = new Query( owner );
        }

        void execute()
        {
            if ( !q ) {
                q = new Query( "select not exists (select * from "
                               "information_schema.table_privileges where "
                               "privilege_type='DELETE' and table_name="
                               "'messages' and grantee=$1) and not exists "
                               "(select u.usename from pg_catalog.pg_class c "
                               "left join pg_catalog.pg_user u on "
                               "(u.usesysid=c.relowner) where c.relname="
                               "'messages' and u.usename=$1) as allowed",
                               this );
                q->bind( 1, Configuration::text( Configuration::DbUser ) );
                q->execute();
            }

            if ( !q->done() )
                return;

            Row * r = q->nextRow();
            if ( q->failed() || !r ||
                 r->getBoolean( "allowed" ) == false )
            {
                String s( "Refusing to start because we have too many "
                          "privileges on the messages table in secure "
                          "mode." );
                result->setError( s );
                l->log( s, Log::Disaster );
                if ( q->failed() ) {
                    l->log( "Query: " + q->description(), Log::Disaster );
                    l->log( "Error: " + q->error(), Log::Disaster );
                }
            }
            else {
                result->setState( Query::Completed );
            }

            result->notify();
        }
    };

    AccessChecker * a = new AccessChecker( owner );
    owner->waitFor( a->result );
    a->execute();
}
