// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "schema.h"

#include "log.h"
#include "field.h"
#include "query.h"
#include "addresscache.h"
#include "transaction.h"
#include "stringlist.h"
#include "allocator.h"
#include "address.h"
#include "dict.h"
#include "md5.h"


class SchemaData
    : public Garbage
{
public:
    SchemaData()
        : l( new Log( Log::Database ) ),
          state( 0 ), substate( 0 ), revision( 0 ),
          lock( 0 ), seq( 0 ), update( 0 ), q( 0 ), t( 0 ),
          result( 0 ), upgrade( false ), commit( true ),
          addressFields( 0 )
    {}

    Log *l;
    int state;
    int substate;
    uint revision;
    Query *lock, *seq, *update, *q;
    Transaction *t;
    Query *result;
    bool upgrade;
    bool commit;
    String version;

    // step-specific variables below

    // for stepTo33
    class AddressField
        : public Garbage
    {
    public:
        AddressField()
            : mailbox( 0 ), uid( 0 ), part( 0 ),
              position( 0 ), address( 0 ), number( 0 ) {}
        uint mailbox;
        uint uid;
        String part;
        uint position;
        uint field;
        Address * address;
        uint number;
    };
    List<AddressField> * addressFields;
};


/*! \class Schema schema.h

    This class manipulates the Oryx database schema. It knows all the
    schema revisions and can upgrade a database to the latest schema
    version automatically.
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
            d->revision = Database::currentRevision();
            d->t->commit();
            d->state = 5;
        }
        else if ( d->revision == Database::currentRevision() ) {
            if ( d->upgrade )
                d->l->log( "Schema is already at revision " +
                           fn( Database::currentRevision() ) +
                           ", no upgrade necessary.",
                           Log::Significant );
            d->result->setState( Query::Completed );
            d->t->commit();
            d->state = 5;
        }
        else if ( d->upgrade && d->revision < Database::currentRevision() ) {
            d->l->log( "Upgrading schema from revision " +
                       fn( d->revision ) + " to revision " +
                       fn( Database::currentRevision() ) + ".",
                       Log::Significant );
            d->state = 2;
        }
        else {
            String s( "The existing schema (revision " );
            s.append( fn( d->revision ) );
            s.append( ") is " );
            if ( d->revision < Database::currentRevision() )
                s.append( "older" );
            else
                s.append( "newer" );
            s.append( " than this server (version " );
            s.append( Configuration::compiledIn( Configuration::Version ) );
            s.append( ") expected (revision " );
            s.append( fn( Database::currentRevision() ) );
            s.append( "). Please " );
            if ( d->revision < Database::currentRevision() )
                s.append( "run 'aox upgrade schema'" );
            else
                s.append( "upgrade" );
            s.append( " or contact support." );
            fail( s );
            d->revision = Database::currentRevision();
            d->t->commit();
            d->state = 5;
        }
    }

    while ( d->revision < Database::currentRevision() ) {
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

            if ( d->revision == Database::currentRevision() ) {
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
                    fn( Database::currentRevision() ) + ".";
            else
                s = "The schema could not be validated.";
            fail( s, d->t->failedQuery() );
        }
        else if ( d->state == 6 ) {
            d->result->setState( Query::Completed );
            d->l->log( "Schema upgraded to revision " +
                       fn( Database::currentRevision() ) + ".",
                       Log::Significant );
        }
        d->state = 7;
    }

    if ( d->state == 7 ) {
        d->state = 42;
        d->result->notify();
    }
}


/*! This private helper logs a \a description of the step currently being made. */

void Schema::describeStep( const String & description )
{
    d->l->log( fn( d->revision ) + "-" + fn( d->revision + 1 ) + ": " +
               description, Log::Significant );
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
    case 26:
        c = stepTo27(); break;
    case 27:
        c = stepTo28(); break;
    case 28:
        c = stepTo29(); break;
    case 29:
        c = stepTo30(); break;
    case 30:
        c = stepTo31(); break;
    case 31:
        c = stepTo32(); break;
    case 32:
        c = stepTo33(); break;
    default:
        d->l->log( "Internal error. Reached impossible revision " +
                   fn( d->revision ) + ".", Log::Disaster );
        c = true;
        break;
    }

    return c;
}


/*! Changes the type of users.login and users.secret to text to remove
    the made-up length restriction on the earlier varchar field.
*/

bool Schema::stepTo2()
{
    if ( d->substate == 0 ) {
        describeStep( "Changing users.login/secret to text." );
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
        describeStep( "Merging bodyparts and binary_parts." );
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
        describeStep( "Creating flags from messages/extra_flags." );
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
        describeStep( "Adding hf_mup, af_mu, fl_mu indices." );
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
        describeStep( "Moving bytes/lines to part_numbers." );
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
        describeStep( "Adding header_fields.position." );
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
        d->l->log( "Making address_fields refer to header_fields." );
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
        describeStep( "Removing recent_messages." );
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
        describeStep( "Altering mailboxes_owner_fkey." );

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
        describeStep( "Deleting revisions." );
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
        describeStep( "Reverting mailboxes_owner_fkey change." );
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
        describeStep( "Creating annotations/annotation_names." );
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
        describeStep( "Creating views/view_messages." );
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
        describeStep( "Altering subscriptions_owner_fkey." );

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
        describeStep( "Creating aliases table." );
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
        describeStep( "Recreating unified aliases table." );
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
        describeStep( "Creating scripts table." );
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
        describeStep( "Creating date_fields table." );
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
    describeStep( "(Not) Populating the date_fields table." );
    return true;
}


/*! Remove unnecessary stuff from annotations. */

bool Schema::stepTo21()
{
    if ( d->substate == 0 ) {
        describeStep( "Removing fields from annotations table." );
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
        describeStep( "Finding flag names that differ only in case." );
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
        describeStep( "Creating deleted_messages table." );
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
        describeStep( "Creating threads/thread_message" );
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
        describeStep( "Creating modsequences table." );
        String dbuser( Configuration::text( Configuration::DbUser ) );
        d->q = new Query( "create sequence nextmodsequence", this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,update on nextmodsequence to " +
                          dbuser, this );
        d->t->enqueue( d->q );
        d->q = new Query( "create table modsequences (mailbox integer "
                          "not null, uid integer not null, modseq bigint "
                          "not null, foreign key (mailbox, uid) references "
                          "messages(mailbox, uid))", this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,insert,update on modsequences to " +
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
        describeStep( "Altering deleted_messages.deleted_at to timestamptz." );
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
        describeStep( "Altering modsequences_mailbox_fkey." );

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


/*! Create the deliveries table. */

bool Schema::stepTo28()
{
    if ( d->substate == 0 ) {
        describeStep( "Creating deliveries table." );
        String dbuser( Configuration::text( Configuration::DbUser ) );
        d->q = new Query( "create table deliveries (id serial primary key,"
                          "recipient integer not null references addresses(id),"
                          "mailbox integer not null, uid integer not null,"
                          "injected_at timestamp with time zone,"
                          "expires_at timestamp with time zone,"
                          "foreign key (mailbox, uid) references "
                          "messages(mailbox, uid) on delete cascade)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,insert,update,delete "
                          "on deliveries to " + dbuser, this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,update on deliveries_id_seq "
                          "to " + dbuser, this );
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


/*! Replace views.suidnext with nextmodseq. */

bool Schema::stepTo29()
{
    if ( d->substate == 0 ) {
        describeStep( "Replacing views.suidnext with nextmodseq." );
        d->q = new Query( "alter table views add nextmodseq bigint", this );
        d->t->enqueue( d->q );
        d->q = new Query( "update views set "
                          "nextmodseq=nextval('nextmodsequence')", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table views alter nextmodseq "
                          "set not null", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table views drop suidnext", this );
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


/*! Create the access_keys table. */

bool Schema::stepTo30()
{
    if ( d->substate == 0 ) {
        describeStep( "Creating access_keys table." );
        String dbuser( Configuration::text( Configuration::DbUser ) );
        d->q = new Query( "create table access_keys (userid integer not null "
                          "references users(id) on delete cascade, mailbox "
                          "integer not null references mailboxes(id) on "
                          "delete cascade, key text not null, "
                          "primary key (userid, mailbox))", this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,insert,delete on access_keys "
                          "to " + dbuser, this );
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


/*! Add indexes on addresses and deleted_messages. */

bool Schema::stepTo31()
{
    if ( d->substate == 0 ) {
        describeStep( "Adding indexes on addresses and deleted_messages." );
        d->q = new Query( "create index ald on addresses(lower(localpart), "
                          "lower(domain))", this );
        d->t->enqueue( d->q );
        d->q = new Query( "analyse addresses", this );
        d->t->enqueue( d->q );
        d->q = new Query( "create index dm_mu on deleted_messages(mailbox, "
                          "uid)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "create index pn_b on part_numbers(bodypart)",
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


/*! Create and populate the unparsed_messages table. */

bool Schema::stepTo33()
{
    if ( d->substate == 0 ) {
        describeStep( "Creating unparsed_messages table (slow)." );
        String dbuser( Configuration::text( Configuration::DbUser ) );
        d->q = new Query( "create table unparsed_messages (bodypart "
                          "integer not null references bodyparts(id) "
                          "on delete cascade)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant insert on unparsed_messages to " +
                          dbuser, this );
        d->t->enqueue( d->q );
        d->q = new Query(
            // this breaks the 80-column limit. that's not its worst problem.
            "insert into unparsed_messages(bodypart) "
            "select distinct pn2.bodypart"
            " from messages m"
            " join header_fields hf on (hf.uid=m.uid and m.mailbox=hf.mailbox)"
            " join address_fields af on (af.uid=m.uid and m.mailbox=af.mailbox)"
            " join addresses a on (af.address=a.id)"
            " join part_numbers pn1 on (pn1.uid=m.uid and m.mailbox=pn1.mailbox)"
            " join part_numbers pn2 on (pn2.uid=m.uid and m.mailbox=pn2.mailbox)"
            " join field_names subject on (hf.field=subject.id)"
            " join field_names \"from\" on (af.field=\"from\".id)"
            " join bodyparts bp on (bp.id=pn1.bodypart)"
            " where pn1.part=1"
            " and pn2.part=2"
            " and subject.name='Subject'"
            " and \"from\".name='From'"
            " and dm.uid is null"
            " and bp.text ilike 'The appended message was received, but could not be stored'"
            " and ((hf.field=subject.id"
            "       and hf.value ilike 'message arrived but could not be stored')"
            "      or (af.field=\"from\".id and a.name='Mail Storage Database'))"
            " order by pn2.bodypart", this );
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


/*! The address_fields table lacks many of the rows it should have had
    in revisions prior to 33. This upgrade removes all existing rows,
    adds a new column with data we need to keep, parses header_fields
    to generate the new rows, and kills the now unnecessary
    header_fields rows.

    Well, actually it doesn't do the last step yet. The
    MessageHeaderFetcher is careful to disregard these rows, so the do
    no harm.
*/

bool Schema::stepTo32()
{
    if ( d->substate == 0 ) {
        describeStep( "Adding missing address_fields rows (slow)." );

        d->q = new Query(
            "create table new_address_fields ("
            "    mailbox     integer not null,"
            "    uid         integer not null,"
            "    part        text not null,"
            "    position    integer not null,"
            "    field       integer not null,"
            "    number      integer not null,"
            "    address     integer not null references addresses(id),"
            "    foreign key (mailbox, uid, part, position, field)"
            "                references header_fields(mailbox, uid, part,"
            "                position, field) on delete cascade"
            ")", 0 );
        d->t->enqueue( d->q );

        String dbuser( Configuration::text( Configuration::DbUser ) );
        d->q = new Query( "grant select,insert on new_address_fields to " +
                          dbuser, 0 );
        d->t->enqueue( d->q );

        // first: all the rows that can be moved into the new table
        // without going through this process
        d->q = new Query(
            "insert into new_address_fields "
            "(mailbox,uid,position,part,field,address,number) "
            "select"
            " hf.mailbox,hf.uid,hf.position,hf.part,hf.field,af.address,0 "
            "from header_fields hf "
            "join address_fields af using"
            " ( mailbox, uid, position, part, field ) "
            "where not hf.value ilike '%,%'", 0 );
        d->t->enqueue( d->q );

        // then: all the ones where we need to think hard in order to
        // determine the address numbering
        d->q = new Query(
            "declare f cursor for "
            "select hf.mailbox,hf.uid,hf.position,hf.part,hf.field,hf.value, "
            "af.address,a.name,a.localpart,a.domain "
            "from header_fields hf "
            "left join address_fields af using"
            " ( mailbox, uid, position, part, field ) "
            "join addresses a on (af.address=a.id) "
            "where hf.field<=$1 "
            "and (hf.part!='' or hf.value ilike '%,%') "
            "order by hf.value, hf.part", 0 );
        d->q->bind( 1, HeaderField::LastAddressField );
        d->t->enqueue( d->q );
        d->substate = 1;
    }

    while ( d->substate < 3 ) {
        if ( d->substate == 1 ) {
            d->q = new Query( "fetch 4096 from f", this );
            d->t->enqueue( d->q );
            d->t->execute();
            d->substate = 2;
            d->addressFields = new List<SchemaData::AddressField>;
            // should we call AddressCache::setup() here to limit the
            // size of the cache somewhat? sounds like a good idea. or
            // maybe a new AddressCache::clear().
        }

        AddressParser * p = 0;
        String v;
        bool didCacheLookup = false;
    
        // in state 2, we take the header fields we get, and process
        // them. this is longwinded.
        Row * r = d->q->nextRow();
        while ( r ) {
            SchemaData::AddressField * af = new SchemaData::AddressField;
            af->mailbox = r->getInt( "mailbox" );
            af->uid = r->getInt( "uid" );
            af->part = r->getString( "part" );
            af->position = r->getInt( "position" );
            af->field = r->getInt( "field" );

            String value = r->getString( "value" );
            if ( value != v ) {
                p = new AddressParser( value );
                v = value;
                didCacheLookup = false;
                // at this point, we could/should check for parse
                // errors. but since this data has already been
                // accepted for the db, let's not.
            }

            if ( r->isNull( "address" ) ) {
                // we have a header_fields row, but no corresponding
                // address_fields rows. let's ask the cache and create
                // as many rows as we'll need.
                if ( !didCacheLookup ) {
                    AddressCache::lookup( d->t, p->addresses(), this );
                    didCacheLookup = true;
                }
                af->number = 0;
                List<Address>::Iterator i( p->addresses() );
                while ( i ) {
                    af->address = i;
                    SchemaData::AddressField * n
                        = new SchemaData::AddressField;
                    n->mailbox = af->mailbox;
                    n->uid = af->uid;
                    n->part = af->part;
                    n->position = af->position;
                    n->field = af->field;
                    n->number = af->number+1;
                    d->addressFields->append( af );
                    af = n;
                    ++i;
                }
            }
            else if ( p->addresses()->count() == 1 ) {
                // we have a single address and its ID. add a row.
                af->number = 0;
                af->address = p->addresses()->firstElement();
                af->address->setId( r->getInt( "address" ) );
                d->addressFields->append( af );
            }
            else {
                // we have a list of addresses and an ID. let's look
                // for the one we have and add it as a row.
                String name = r->getString( "name" );
                String localpart = r->getString( "localpart" );
                String domain = r->getString( "domain" );
                List<Address>::Iterator i( p->addresses() );
                uint number = 0;
                bool found = false;
                while ( i && !found ) {
                    if ( localpart == i->localpart() &&
                         domain == i->domain() &&
                         name == i->name() ) {
                        af->address = i;
                        i->setId( r->getInt( "address" ) );
                        af->number = number;
                        d->addressFields->append( af );
                        found = true;
                    }
                    ++number;
                    ++i;
                }
            }
            r = d->q->nextRow();
        }

        if ( !d->q->done() )
            return false;

        // we're still in state 2. let's now see whether we have
        // unresolved address IDs.
        bool unresolved = false;
        List<SchemaData::AddressField>::Iterator i( d->addressFields );
        while ( i && !unresolved ) {
            if ( !i->address->id() )
                unresolved = true;
            ++i;
        }
        if ( unresolved )
            return false;

        // we're now ready to submit the new address fields. the copy
        // below generally has 8000 or more rows each time we run
        // through this (except the last of course).
        Query * q
            = new Query( "copy new_address_fields "
                         "(mailbox,uid,part,position,field,address,number) "
                         "from stdin with binary", 0 );
        i = d->addressFields->first();
        while ( i ) {
            q->bind( 1, i->mailbox, Query::Binary );
            q->bind( 2, i->uid, Query::Binary );
            q->bind( 3, i->part, Query::Binary );
            q->bind( 4, i->position, Query::Binary );
            q->bind( 5, i->field, Query::Binary );
            q->bind( 6, i->address->id(), Query::Binary );
            q->bind( 7, i->number, Query::Binary );
            q->submitLine();
            ++i;
        }

        d->t->enqueue( q );

        // should we step back and get some more rows, or are we done?
        if ( d->q->rows() ) {
            d->substate = 1;
        }
        else {
            d->t->enqueue( new Query( "close f", this ) );
            d->substate = 3;
        }
    }

    if ( d->substate == 3 ) {
        // rejoice. that was hard work and we're almost done!
        d->q = new Query( "drop table address_fields", 0 );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table new_address_fields "
                          "rename to address_fields", 0 );
        d->t->enqueue( d->q );
        d->q = new Query( "create index af_mu on "
                          "address_fields (mailbox, uid)", this );
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


/*! Changes the foreign keys in address_fields so it references
    part_numbers directly instead of via header_fields, and deletes
    the header_fields that also exist as address_fields.

    This is not part of stepTo32() so that stepTo32() can be debugged
    in peace.
*/

bool Schema::stepTo34()
{
    if ( d->substate == 0 ) {
        describeStep( "Removing header_fields rows "
                      "that duplicate address_fields rows (slow)." );
        d->q = new Query( "alter table address_fields drop constraint XXX", 0 );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table address_fields add constraint XXX", 0 );
        d->t->enqueue( d->q );
        d->q = new Query( "delete from header_fields where "
                          "(mailbox,uid,part,position,field) in "
                          "(select mailbox,uid,part,position,field"
                          " from address_fields)", this );
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
