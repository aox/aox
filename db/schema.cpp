// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "schema.h"

#include "schemachecker.h"
#include "transaction.h"
#include "stringlist.h"
#include "allocator.h"
#include "address.h"
#include "ustring.h"
#include "granter.h"
#include "field.h"
#include "query.h"
#include "dict.h"
#include "log.h"
#include "md5.h"
#include "utf.h"

#include <stdio.h>


class SchemaData
    : public Garbage
{
public:
    SchemaData()
        : l( new Log ),
          state( 0 ), substate( 0 ), revision( 0 ),
          lock( 0 ), seq( 0 ), update( 0 ), q( 0 ), t( 0 ),
          result( 0 ), unparsed( 0 ), upgrade( false ), commit( true ),
          quid( 0 ), undel( 0 ), row( 0 ), lastMailbox( 0 ), count( 0 ),
          uidnext( 0 ), nextmodseq( 0 ), granter( 0 )
    {
        schema = Configuration::text( Configuration::DbSchema );
        dbuser = Configuration::text( Configuration::DbUser ).quoted();
    }

    Log *l;
    int state;
    int substate;
    uint revision;
    Query *lock, *seq, *update, *q;
    Transaction *t;
    Query * result;
    Query * unparsed;
    bool upgrade;
    bool commit;
    String version;
    String dbuser;
    String schema;

    // The following state variables are needed by stepTo72().

    Query * quid;
    Query * undel;
    Row * row;
    uint lastMailbox;
    uint count;
    uint uidnext;
    int64 nextmodseq;

    Granter * granter;
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
            d->state = 7;
        }
        else if ( d->revision == Database::currentRevision() ) {
            if ( d->upgrade )
                d->l->log( "Schema is already at revision " +
                           fn( Database::currentRevision() ) +
                           ", no upgrade necessary.",
                           Log::Significant );
            d->result->setState( Query::Completed );
            d->t->commit();
            d->state = 7;
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
            s.appendNumber( d->revision );
            s.append( ") is " );
            if ( d->revision < Database::currentRevision() )
                s.append( "older" );
            else
                s.append( "newer" );
            s.append( " than this server (version " );
            s.append( Configuration::compiledIn( Configuration::Version ) );
            s.append( ") expected (revision " );
            s.appendNumber( Database::currentRevision() );
            s.append( "). Please " );
            if ( d->revision < Database::currentRevision() )
                s.append( "run 'aox upgrade schema'" );
            else
                s.append( "upgrade" );
            s.append( " or contact support." );
            fail( s );
            d->revision = Database::currentRevision();
            d->t->commit();
            d->state = 7;
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

            d->l->log( "Done.", Log::Debug );
            d->substate = 0;
            d->state = 2;
            d->revision++;

            if ( d->revision == Database::currentRevision() ) {
                d->state = 5;
                break;
            }
        }
    }

    if ( d->state == 5 ) {
        if ( d->dbuser.unquoted() ==
             Configuration::text( Configuration::DbOwner ) ) {
            d->l->log( "Warning: db-user is the same as db-owner",
                       Log::Significant );
        }

        d->l->log( "Checking database, adjusting privileges.",
                   Log::Significant );
        Granter * g = new Granter( d->dbuser.unquoted(), d->t );
        g->notify();

        // SchemaChecker * c = new SchemaChecker( d->t );
        // c->notify();

        d->state = 6;
        if ( d->commit )
            d->t->commit();
        else
            d->t->rollback();
    }

    if ( d->state == 6 ) {
        if ( !d->t->done() )
            return;

        if ( !d->unparsed && !d->t->failed() && d->upgrade ) {
            d->unparsed = new Query( "select count(*) as unparsed "
                                     "from unparsed_messages", this );
            d->unparsed->execute();
        }

        if ( d->unparsed && !d->unparsed->done() )
            return;

        if ( d->unparsed && d->unparsed->hasResults() ) {
            Row * r = d->unparsed->nextRow();
            int64 u = r->getBigint( "unparsed" );
            if ( u )
                d->l->log( "Please run 'aox reparse' (or 'aox reparse -e') "
                           "when Archiveopteryx has been started. "
                           "There are " + fn( u ) + " unparsed messages now. ",
                           Log::Significant );
        }

        d->state = 7;
    }

    if ( d->state == 7 ) {
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
        else if ( d->upgrade ) {
            String s( "Schema upgraded to revision " );
            s.appendNumber( Database::currentRevision() );
            if ( !d->commit )
                s.append( ", but not committed" );
            s.append( "." );

            d->l->log( s, Log::Significant );
            d->result->setState( Query::Completed );
        }

        d->state = 8;
    }

    if ( d->state == 8 ) {
        d->state = 42;
        d->result->notify();
    }
}


/*! This private helper logs a \a description of the step currently
    being made.
*/

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
    case 33:
        c = stepTo34(); break;
    case 34:
        c = stepTo35(); break;
    case 35:
        c = stepTo36(); break;
    case 36:
        c = stepTo37(); break;
    case 37:
        c = stepTo38(); break;
    case 38:
        c = stepTo39(); break;
    case 39:
        c = stepTo40(); break;
    case 40:
        c = stepTo41(); break;
    case 41:
        c = stepTo42(); break;
    case 42:
        c = stepTo43(); break;
    case 43:
        c = stepTo44(); break;
    case 44:
        c = stepTo45(); break;
    case 45:
        c = stepTo46(); break;
    case 46:
        c = stepTo47(); break;
    case 47:
        c = stepTo48(); break;
    case 48:
        c = stepTo49(); break;
    case 49:
        c = stepTo50(); break;
    case 50:
        c = stepTo51(); break;
    case 51:
        c = stepTo52(); break;
    case 52:
        c = stepTo53(); break;
    case 53:
        c = stepTo54(); break;
    case 54:
        c = stepTo55(); break;
    case 55:
        c = stepTo56(); break;
    case 56:
        c = stepTo57(); break;
    case 57:
        c = stepTo58(); break;
    case 58:
        c = stepTo59(); break;
    case 59:
        c = stepTo60(); break;
    case 60:
        c = stepTo61(); break;
    case 61:
        c = stepTo62(); break;
    case 62:
        c = stepTo63(); break;
    case 63:
        c = stepTo64(); break;
    case 64:
        c = stepTo65(); break;
    case 65:
        c = stepTo66(); break;
    case 66:
        c = stepTo67(); break;
    case 67:
        c = stepTo68(); break;
    case 68:
        c = stepTo69(); break;
    case 69:
        c = stepTo70(); break;
    case 70:
        c = stepTo71(); break;
    case 71:
        c = stepTo72(); break;
    case 72:
        c = stepTo73(); break;
    case 73:
        c = stepTo74(); break;
    case 74:
        c = stepTo75(); break;
    case 75:
        c = stepTo76(); break;
    case 76:
        c = stepTo77(); break;
    case 77:
        c = stepTo78(); break;
    case 78:
        c = stepTo79(); break;
    case 79:
        c = stepTo80(); break;
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
    }

    return true;
}


/*! Adds the modsequences table. */

bool Schema::stepTo25()
{
    if ( d->substate == 0 ) {
        describeStep( "Creating modsequences table." );
        d->q = new Query( "create sequence nextmodsequence", this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,update on nextmodsequence to " +
                          d->dbuser, this );
        d->t->enqueue( d->q );
        d->q = new Query( "create table modsequences (mailbox integer "
                          "not null, uid integer not null, modseq bigint "
                          "not null, foreign key (mailbox, uid) references "
                          "messages(mailbox, uid))", this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,insert,update on modsequences to " +
                          d->dbuser, this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
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
    }

    return true;
}


/*! Create the deliveries table. */

bool Schema::stepTo28()
{
    if ( d->substate == 0 ) {
        describeStep( "Creating deliveries table." );
        d->q = new Query( "create table deliveries (id serial primary key,"
                          "recipient integer not null references addresses(id),"
                          "mailbox integer not null, uid integer not null,"
                          "injected_at timestamp with time zone,"
                          "expires_at timestamp with time zone,"
                          "foreign key (mailbox, uid) references "
                          "messages(mailbox, uid) on delete cascade)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,insert,update,delete "
                          "on deliveries to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,update on deliveries_id_seq "
                          "to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
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
    }

    return true;
}


/*! Create the access_keys table. */

bool Schema::stepTo30()
{
    if ( d->substate == 0 ) {
        describeStep( "Creating access_keys table." );
        d->q = new Query( "create table access_keys (userid integer not null "
                          "references users(id) on delete cascade, mailbox "
                          "integer not null references mailboxes(id) on "
                          "delete cascade, key text not null, "
                          "primary key (userid, mailbox))", this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,insert,delete on access_keys "
                          "to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
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
        describeStep( "Numbering address_fields rows (slow)." );

        d->q = new Query( "alter table address_fields add number integer", 0 );
        d->t->enqueue( d->q );

        d->q = new Query( "set enable_mergejoin to false", 0 );
        d->t->enqueue( d->q );

        d->q = new Query( "set enable_hashjoin to false", 0 );
        d->t->enqueue( d->q );

        d->q =
            new Query( "update address_fields set number=0 where "
                       "(mailbox,uid,part,position,field) in "
                       "(select mailbox,uid,part,position,field from"
                       " address_fields group by"
                       " mailbox,uid,part,position,field"
                       " having count(*)=1)", 0 );
        d->t->enqueue( d->q );

        d->q = new Query( "set enable_mergejoin to true", 0 );
        d->t->enqueue( d->q );

        d->q = new Query( "set enable_hashjoin to true", 0 );
        d->t->enqueue( d->q );

        String last( fn( HeaderField::LastAddressField ) );
        d->q = new Query( "create index hf_fp on header_fields(field) where "
                          "field<=" + last + " and part<>''", 0 );
        d->t->enqueue( d->q );

        d->q =
            new Query( "update address_fields set number=null where "
                       "(mailbox,uid) in (select distinct mailbox,uid"
                       " from header_fields where field<=" + last +
                       " and part<>'')", 0 );
        d->t->enqueue( d->q );

        String constraint = "address_fields_mailbox_fkey";
        if ( d->version.startsWith( "7" ) )
            constraint = "$2";

        d->q =
            new Query( "alter table address_fields drop constraint "
                       "\"" + constraint + "\"", 0 );
        d->t->enqueue( d->q );

        d->q =
            new Query( "alter table address_fields add constraint "
                       "address_fields_mailbox_fkey foreign key "
                       "(mailbox,uid,part) references part_numbers "
                       "(mailbox,uid,part) on delete cascade", 0 );
        d->t->enqueue( d->q );

        d->q =
            new Query( "delete from header_fields where field<=" + last +
                       " and (mailbox,uid) in "
                       "(select mailbox,uid from address_fields group by"
                       " mailbox,uid having count(*)=count(number))", 0 );
        d->t->enqueue( d->q );

        d->q = new Query( "drop index hf_fp", this );
        d->t->enqueue( d->q );

        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Add some indexes to speed up message deletion. */

bool Schema::stepTo33()
{
    if ( d->substate == 0 ) {
        describeStep( "Adding indexes to speed up message deletion." );
        d->q = new Query( "create index df_mu on date_fields(mailbox,uid)",
                          this );
        d->t->enqueue( d->q );
        d->q = new Query( "create index vm_mu on view_messages (source,suid)",
                          this );
        d->t->enqueue( d->q );
        d->q = new Query( "create index ms_mu on modsequences(mailbox,uid)",
                          this );
        d->t->enqueue( d->q );
        d->q = new Query( "create index dm_mud on deleted_messages"
                          "(mailbox,uid,deleted_at)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "drop index dm_mu", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Add tried_at to deliveries. */

bool Schema::stepTo34()
{
    if ( d->substate == 0 ) {
        describeStep( "Adding deliveries.tried_at." );
        d->q = new Query( "alter table deliveries add tried_at "
                          "timestamp with time zone", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Add sender to deliveries too. */

bool Schema::stepTo35()
{
    if ( d->substate == 0 ) {
        describeStep( "Adding deliveries.sender." );
        d->q = new Query( "alter table deliveries add sender integer "
                          "references addresses(id)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table deliveries alter sender set "
                          "not null", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Grant "update" on deliveries to aox, because although stepTo28() did
    that, schema/grant-privileges did not.
*/

bool Schema::stepTo36()
{
    if ( d->substate == 0 ) {
        describeStep( "Granting update on deliveries." );
        d->q = new Query( "grant update on deliveries to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Create the unparsed_messages table if it doesn't exist already.
    After this revision, the table exists, but is unfilled; and the
    upgraded schema and schema.pg ought to be in sync.
*/

bool Schema::stepTo37()
{
    if ( d->substate == 0 ) {
        describeStep( "Creating unparsed_messages if necessary" );
        d->q = new Query( "select * from information_schema.tables where "
                          "table_name='unparsed_messages'", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        if ( !d->q->hasResults() ) {
            d->q =
                new Query( "create table unparsed_messages ("
                           "bodypart integer not null references "
                           "bodyparts(id) on delete cascade, "
                           "primary key(bodypart))", this );
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
    }

    return true;
}


/*! Grant insert on unparsed_messages. */

bool Schema::stepTo38()
{
    if ( d->substate == 0 ) {
        describeStep( "Granting insert on unparsed_messages" );
        d->q = new Query( "grant insert on unparsed_messages "
                          "to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Add a unique constraint to scripts. */

bool Schema::stepTo39()
{
    if ( d->substate == 0 ) {
        describeStep( "Adding unique constraint to scripts" );
        d->q =
            new Query( "alter table scripts add constraint "
                       "scripts_owner_key unique(owner,name)", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Relax the deleted_messages.deleted_by constraint. */

bool Schema::stepTo40()
{
    if ( d->substate == 0 ) {
        describeStep( "Dropping NOT NULL on deleted_messages.deleted_by" );
        d->q =
            new Query( "alter table deleted_messages alter deleted_by "
                       "drop not null", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Populate unparsed_messages. */

bool Schema::stepTo41()
{
    if ( d->substate == 0 ) {
        describeStep( "Populating unparsed_messages" );
        d->q =
            new Query(
                "insert into unparsed_messages select distinct p.bodypart "
                "from part_numbers p left join deleted_messages dm "
                "using (mailbox,uid) left join unparsed_messages um "
                "using (bodypart) "
                "join header_fields hf using (mailbox,uid) "
                "where p.part='2' and p.bodypart is not null and "
                "dm.uid is null and um.bodypart is null "
                "and hf.part='' and hf.field=20 and "
                "(hf.value='Message arrived but could not be stored' "
                "or hf.value like 'Unparsable message:%')", this
            );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Insert modsequences for any messages that don't have them. */

bool Schema::stepTo42()
{
    if ( d->substate == 0 ) {
        describeStep( "Populating modsequences for old messages" );
        d->q =
            new Query(
                "insert into modsequences (mailbox,uid,modseq) "
                "select mailbox,uid,(select nextval('nextmodsequence')) "
                "from messages m left join modsequences ms "
                "using (mailbox,uid) where ms.uid is null", this
            );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Make nextmodseq be per-mailbox. */

bool Schema::stepTo43()
{
    if ( d->substate == 0 ) {
        describeStep( "Assigning nextmodseq for each mailbox" );
        d->q = new Query( "alter table mailboxes add nextmodseq bigint", this );
        d->t->enqueue( d->q );
        d->q = new Query( "update mailboxes set nextmodseq="
                          "(select nextval('nextmodsequence'))", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table mailboxes alter nextmodseq "
                          "set not null", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table mailboxes alter nextmodseq "
                          "set default 1", this );
        d->t->enqueue( d->q );
        d->q = new Query( "drop sequence nextmodsequence", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Add some primary keys (the easy ones). */

bool Schema::stepTo44()
{
    if ( d->substate == 0 ) {
        describeStep( "Adding primary keys to some tables" );
        d->q = new Query( "alter table annotations add primary key "
                          "(mailbox,uid,owner,name)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table modsequences add primary key "
                          "(mailbox,uid)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "drop index ms_mu", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table permissions add primary key "
                          "(mailbox,identifier)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table group_members add primary key "
                          "(groupname,member)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table thread_members add primary key "
                          "(thread,mailbox,uid)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table mailstore add primary key "
                          "(revision)", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Add an index on users.login. */

bool Schema::stepTo45()
{
    if ( d->substate == 0 ) {
        describeStep( "Adding an index on users.login" );
        d->q = new Query( "create index u_l on users(lower(login))", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Remove duplicates from deleted_messages, and add a primary key. */

bool Schema::stepTo46()
{
    if ( d->substate == 0 ) {
        describeStep( "Adding a primary key to deleted_messages" );
        d->q = new Query( "create aggregate array_accum "
                          "(basetype=anyelement, sfunc=array_append,"
                          " stype=anyarray, initcond='{}')", this );
        d->t->enqueue( d->q );
        d->q = new Query( "delete from deleted_messages where ctid in "
                          "(select d.ctid from deleted_messages d join "
                          "(select mailbox,uid,array_accum(ctid) as tids "
                          "from deleted_messages group by mailbox,uid "
                          "having count(*)>1) ds using (mailbox,uid) where "
                          "not (d.ctid=tids[1]))", this );
        d->t->enqueue( d->q );
        d->q = new Query( "drop aggregate array_accum (anyelement)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table deleted_messages add "
                          "primary key (mailbox,uid)", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Unconstrain annotations.owner and add a surrogate key. */

bool Schema::stepTo47()
{
    if ( d->substate == 0 ) {
        describeStep( "Adding a surrogate key to annotations" );
        d->q = new Query( "alter table annotations drop constraint "
                          "annotations_pkey", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table annotations alter owner "
                          "drop not null", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table annotations add id serial", this );
        d->t->enqueue( d->q );
        d->q = new Query( "update annotations set id=nextval("
                          "pg_get_serial_sequence('annotations','id'))",
                          this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table annotations alter id "
                          "set not null", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table annotations add "
                          "unique (mailbox,uid,owner,name)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table annotations add "
                          "primary key (id)", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Grant select,update on annotations_id_seq. */

bool Schema::stepTo48()
{
    if ( d->substate == 0 ) {
        describeStep( "Granting privileges on annotations_id_seq" );
        d->q = new Query( "grant select,update on annotations_id_seq "
                          "to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Grant privileges on threads and thread_members. */

bool Schema::stepTo49()
{
    if ( d->substate == 0 ) {
        describeStep( "Granting privileges on thread*" );
        d->q = new Query( "grant select,insert on threads "
                          "to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,insert on thread_members "
                          "to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,update on threads_id_seq "
                          "to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Add deliveries.delivered_at. */

bool Schema::stepTo50()
{
    if ( d->substate == 0 ) {
        describeStep( "Adding deliveries.delivered_at" );
        d->q = new Query( "alter table deliveries add delivered_at "
                          "timestamp with time zone", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Split delivery_recipients away from deliveries. */

bool Schema::stepTo51()
{
    if ( d->substate == 0 ) {
        describeStep( "Creating delivery_recipients" );
        d->q = new Query( "create table delivery_recipients ("
                          "id serial primary key, delivery integer "
                          "not null references deliveries(id) on delete "
                          "cascade, recipient integer not null references "
                          "addresses(id), status text)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select, insert, update on "
                          "delivery_recipients to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table deliveries drop recipient", this );
        d->t->enqueue( d->q );
        describeStep( "Emptying the spool" );
        d->q = new Query( "delete from deliveries", this );
        d->t->enqueue( d->q );
        d->q =
            new Query( "insert into deleted_messages (mailbox,uid,reason) "
                       "select mailbox,uid,'spool emptied' from messages "
                       "join mailboxes on (mailbox=id) where "
                       "name='/archiveopteryx/spool'", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Add delivery_recipients.action and last_attempt. */

bool Schema::stepTo52()
{
    if ( d->substate == 0 ) {
        describeStep( "Adding delivery_recipients.action/last_attempt" );
        d->q = new Query( "alter table deliveries drop delivered_at", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table delivery_recipients add "
                          "last_attempt timestamp with time zone", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table delivery_recipients add "
                          "action integer not null default 0", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! We need permissions on the delivery_recipients sequence too. */

bool Schema::stepTo53()
{
    if ( d->substate == 0 ) {
        describeStep( "Granting privileges on delivery_recipients_id_seq" );
        d->q = new Query( "grant select, update on "
                          "delivery_recipients_id_seq to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Make (mailbox,uid) unique in deliveries. */

bool Schema::stepTo54()
{
    if ( d->substate == 0 ) {
        describeStep( "Making (mailbox,uid) unique in deliveries" );
        d->q = new Query( "alter table deliveries add unique(mailbox,uid)",
                          this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Convert mUTF-7 mailbox names to UTF-8. */

bool Schema::stepTo55()
{
    if ( d->substate == 0 ) {
        describeStep( "Converting mUTF-7 mailbox names to UTF-8" );
        d->q = new Query( "select id, name from mailboxes where "
                          "name like '%&%'", this );
        d->t->enqueue( d->q );
        d->update = 0;
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        while ( d->q->hasResults() ) {
            Row * r = d->q->nextRow();

            MUtf7Codec mu;
            Utf8Codec u;

            String oldName( r->getString( "name" ) );
            String newName( u.fromUnicode( mu.toUnicode( oldName ) ) );

            if ( mu.wellformed() && oldName != newName ) {
                Query * q =
                    new Query( "update mailboxes set name=$1 "
                               "where id=$2", this );
                d->update = q;
                q->bind( 1, newName );
                q->bind( 2, r->getInt( "id" ) );
                d->t->enqueue( q );
                d->t->execute();
            }
        }

        if ( !d->q->done() )
            return false;

        d->substate = 2;
    }

    if ( d->substate == 2 ) {
        if ( d->update && !d->update->done() )
            return false;
    }

    return true;
}


/*! Create the vacation_responses table. */

bool Schema::stepTo56()
{
    if ( d->substate == 0 ) {
        describeStep( "Creating vacation_responses table." );
        d->q = new Query( "create table vacation_responses (id serial "
                          "primary key,sent_from integer not null references "
                          "addresses(id),sent_to integer not null references "
                          "addresses(id),expires_at timestamp with time zone "
                          "default current_timestamp+interval '7 days',"
                          "handle text)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,insert on vacation_responses "
                          "to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,update on vacation_responses_id_seq "
                          "to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Rename vacation_responses to autoresponses. (We do this by dropping
    the old table and creating a new one, so that the sequence is also
    renamed.)
*/

bool Schema::stepTo57()
{
    if ( d->substate == 0 ) {
        describeStep( "Renaming vacation_responses to autoresponses." );
        d->q = new Query( "drop table vacation_responses", this );
        d->t->enqueue( d->q );
        d->q = new Query( "create table autoresponses (id serial "
                          "primary key,sent_from integer not null references "
                          "addresses(id),sent_to integer not null references "
                          "addresses(id),expires_at timestamp with time zone "
                          "default current_timestamp+interval '7 days',"
                          "handle text)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,insert on autoresponses "
                          "to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,update on autoresponses_id_seq "
                          "to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Add a missing "on delete cascade" clause to scripts. */

bool Schema::stepTo58()
{
    if ( d->substate == 0 ) {
        describeStep( "Adding missing 'on delete cascade' to scripts." );
        d->q = new Query( "alter table scripts drop constraint "
                          "\"scripts_owner_fkey\"", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table scripts add constraint "
                          "scripts_owner_fkey foreign key (owner) "
                          "references users(id) on delete cascade",
                          this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Delete duplicate addresses: By mistake the unique index used a
    case-sensitive domain. We keep the oldest version seen.
*/

bool Schema::stepTo59()
{
    if ( d->substate == 0 ) {
        describeStep( "Deleting duplicate addresses." );
        d->q = new Query(
            "select a.localpart, a.domain, b.domain as domain2, "
            "a.id as original, b.id as duplicate "
            "from addresses a, addresses b "
            "where a.id<b.id and a.name=b.name "
            "and a.localpart=b.localpart "
            "and lower(a.domain)=lower(b.domain)", this );
        d->t->enqueue( d->q );
        d->t->execute();
        d->substate = 1;
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;

        PreparedStatement af ( "update address_fields "
                               "set address=$1 where address=$2" );
        PreparedStatement aliases( "update aliases "
                                   "set address=$1 where address=$2" );
        PreparedStatement deliveries( "update deliveries "
                                      "set sender=$1 where sender=$2" );
        PreparedStatement dr( "update delivery_recipients "
                              "set recipient=$1 where recipient=$2" );
        PreparedStatement arf( "update autoresponses "
                               "set sent_from=$1 where sent_from=$2" );
        PreparedStatement art( "update autoresponses "
                               "set sent_to=$1 where sent_to=$2" );
        String dfa;

        Query * q;
        Row * r = d->q->nextRow();
        while ( r ) {
            uint original = r->getInt( "original" );
            uint duplicate = r->getInt( "duplicate" );
            d->l->log( "Changing " +
                       r->getString( "localpart" ) + "@" +
                       r->getString( "domain2" ) + " to " +
                       r->getString( "localpart" ) + "@" +
                       r->getString( "domain" ) + "@" );
            q = new Query( af, 0 );
            q->bind( 1, original );
            q->bind( 1, duplicate );
            d->t->enqueue( q );
            q = new Query( aliases, 0 );
            q->bind( 1, original );
            q->bind( 1, duplicate );
            d->t->enqueue( q );
            q = new Query( deliveries, 0 );
            q->bind( 1, original );
            q->bind( 1, duplicate );
            d->t->enqueue( q );
            q = new Query( dr, 0 );
            q->bind( 1, original );
            q->bind( 1, duplicate );
            d->t->enqueue( q );
            q = new Query( arf, 0 );
            q->bind( 1, original );
            q->bind( 1, duplicate );
            d->t->enqueue( q );
            q = new Query( art, 0 );
            q->bind( 1, original );
            q->bind( 1, duplicate );
            d->t->enqueue( q );
            if ( dfa.isEmpty() )
                dfa = "delete from addresses where id=";
            else
                dfa.append( " or id=" );
            dfa.appendNumber( duplicate );
            r = d->q->nextRow();
        }

        q = new Query( dfa, 0 );
        d->t->enqueue( q );

        q = new Query( "alter table addresses drop constraint "
                       "addresses_name_key", 0 );
        d->t->enqueue( q );
        q = new Query( "create unique index addresses_nld_key "
                       "on addresses(name,localpart,lower(domain))",
                       this );
        d->t->enqueue( q );
        d->t->execute();
        d->substate = 2;
    }

    if ( d->substate == 2 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Split messages into two, and clean up the resulting mess. */

bool Schema::stepTo60()
{
    if ( d->substate == 0 ) {
        describeStep( "Splitting the messages table (may be very slow)." );

        // First, we'll add messages.id and make it a candidate key so
        // that we can refer to it from other tables. Then we'll create
        // the new mailbox_messages table.

        describeStep( "1. Separating messages and mailbox_messages" );

        d->q = new Query( "alter table messages add id serial", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table messages alter id set not null", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table messages add unique(id)", this );
        d->t->enqueue( d->q );

        d->q = new Query( "create table mailbox_messages (mailbox integer not "
                          "null references mailboxes(id),uid integer not null,"
                          "message integer not null references messages(id),"
                          "idate integer not null,modseq bigint not null,"
                          "primary key(mailbox,uid))", this );
        d->t->enqueue( d->q );

        d->q = new Query( "grant select,insert,update on mailbox_messages "
                          "to " + d->dbuser, this );
        d->t->enqueue( d->q );

        d->q = new Query( "insert into mailbox_messages "
                          "(mailbox,uid,message,idate,modseq) "
                          "select mailbox,uid,messages.id,idate,modseq from "
                          "messages join modsequences using (mailbox,uid) "
                          "left join deleted_messages using (mailbox,uid) "
                          "where deleted_messages is null", this );
        d->t->enqueue( d->q );

        d->q = new Query( "alter table messages drop idate", this );
        d->t->enqueue( d->q );

        // Fetch the names of all foreign key references to messages.

        d->q = new Query( "select d.relname::text,c.conname::text,"
                          "pg_get_constraintdef(c.oid) as condef "
                          "from pg_constraint c join pg_class d "
                          "on (c.conrelid=d.oid) join pg_class e "
                          "on (c.confrelid=e.oid) where c.contype='f' "
                          "and e.relname='messages'", this );
        d->t->enqueue( d->q );

        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;

        describeStep( "2. Updating foreign key references" );

        if ( d->q->failed() || d->q->rows() == 0 ) {
            fail( "Couldn't fetch references to messages", d->q );
            d->substate = 42;
        }
        else {
            Dict<String> constraints;

            while ( d->q->hasResults() ) {
                Row * r = d->q->nextRow();
                constraints.insert(
                    r->getString( "relname" ),
                    new String( r->getString( "conname" ) )
                );
            }

            d->q = new Query( "alter table part_numbers drop constraint " +
                              constraints.find( "part_numbers" )->quoted(),
                              this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table date_fields drop constraint " +
                              constraints.find( "date_fields" )->quoted(),
                              this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table thread_members drop constraint " +
                              constraints.find( "thread_members" )->quoted(),
                              this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table flags drop constraint " +
                              constraints.find( "flags" )->quoted(), this );
            d->t->enqueue( d->q );

            d->q = new Query( "delete from flags using deleted_messages d "
                              "where flags.mailbox=d.mailbox and "
                              "flags.uid=d.uid", this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table flags add constraint "
                              "flags_mailbox_fkey foreign key "
                              "(mailbox,uid) references "
                              "mailbox_messages (mailbox,uid) "
                              "on delete cascade", this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table annotations drop constraint " +
                              constraints.find( "annotations" )->quoted(),
                              this );
            d->t->enqueue( d->q );

            d->q = new Query( "delete from annotations using "
                              "deleted_messages d where "
                              "annotations.mailbox=d.mailbox and "
                              "annotations.uid=d.uid",
                              this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table annotations add constraint "
                              "annotations_mailbox_fkey foreign key "
                              "(mailbox,uid) references "
                              "mailbox_messages (mailbox,uid) "
                              "on delete cascade", this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table view_messages drop constraint " +
                              constraints.find( "view_messages" )->quoted(),
                              this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table deleted_messages drop constraint " +
                              constraints.find( "deleted_messages" )->quoted(),
                              this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table modsequences drop constraint " +
                              constraints.find( "modsequences" )->quoted(),
                              this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table deliveries drop constraint " +
                              constraints.find( "deliveries" )->quoted(),
                              this );
            d->t->enqueue( d->q );

            d->q = new Query( "select d.relname::text,c.conname::text,"
                              "pg_get_constraintdef(c.oid) as condef "
                              "from pg_constraint c join pg_class d "
                              "on (c.conrelid=d.oid) join pg_class e "
                              "on (c.confrelid=e.oid) where c.contype='f' "
                              "and e.relname='part_numbers'", this );
            d->t->enqueue( d->q );

            d->substate = 2;
            d->t->execute();
        }
    }

    if ( d->substate == 2 ) {
        if ( !d->q->done() )
            return false;

        describeStep( "3. Updating part_numbers and "
                      "header/address/date_fields" );

        if ( d->q->failed() || d->q->rows() == 0 ) {
            fail( "Couldn't fetch references to part_numbers", d->q );
            d->substate = 42;
        }
        else {
            Dict<String> constraints;

            while ( d->q->hasResults() ) {
                Row * r = d->q->nextRow();
                constraints.insert(
                    r->getString( "relname" ),
                    new String( r->getString( "conname" ) )
                );
            }

            d->q = new Query( "alter table header_fields drop constraint " +
                              constraints.find( "header_fields" )->quoted(),
                              this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table address_fields drop constraint " +
                              constraints.find( "address_fields" )->quoted(),
                              this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table part_numbers add message "
                              "integer", this );
            d->t->enqueue( d->q );

            d->q = new Query( "update part_numbers set message=m.id "
                              "from messages m where "
                              "part_numbers.mailbox=m.mailbox and "
                              "part_numbers.uid=m.uid", this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table part_numbers alter message "
                              "set not null", this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table part_numbers add constraint "
                              "part_numbers_message_fkey foreign key "
                              "(message) references messages(id) "
                              "on delete cascade", this );
            d->t->enqueue( d->q );

            d->q = new Query( "select d.relname::text,c.conname::text,"
                              "pg_get_constraintdef(c.oid) as condef "
                              "from pg_constraint c join pg_class d "
                              "on (c.conrelid=d.oid) where c.contype='p' "
                              "and d.relname='part_numbers'", this );
            d->t->enqueue( d->q );

            d->substate = 3;
            d->t->execute();
        }
    }

    if ( d->substate == 3 ) {
        if ( !d->q->done() )
            return false;

        if ( d->q->failed() || d->q->rows() != 1 ) {
            fail( "Couldn't fetch primary key for part_numbers", d->q );
            d->substate = 42;
        }
        else {
            Row * r = d->q->nextRow();

            d->q = new Query( "alter table part_numbers drop constraint " +
                              r->getString( "conname" ).quoted(), this );
            d->t->enqueue( d->q );
            d->q = new Query( "alter table part_numbers add constraint "
                              "part_numbers_pkey primary key (message,part)",
                              this );
            d->t->enqueue( d->q );

            d->q = new Query( "select d.relname::text,c.conname::text,"
                              "pg_get_constraintdef(c.oid) as condef "
                              "from pg_constraint c join pg_class d "
                              "on (c.conrelid=d.oid) where c.contype='u' "
                              "and d.relname='header_fields'", this );
            d->t->enqueue( d->q );

            d->substate = 4;
            d->t->execute();
        }
    }

    if ( d->substate == 4 ) {
        if ( !d->q->done() )
            return false;

        if ( d->q->failed() || d->q->rows() == 0 ) {
            fail( "Couldn't fetch unique constraint on header_fields", d->q );
            d->substate = 42;
        }
        else {
            Dict<String> constraints;

            while ( d->q->hasResults() ) {
                Row * r = d->q->nextRow();
                constraints.insert(
                    r->getString( "relname" ),
                    new String( r->getString( "conname" ) )
                );
            }

            d->q = new Query( "alter table header_fields drop constraint " +
                              constraints.find( "header_fields" )->quoted(),
                              this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table header_fields add message "
                              "integer", this );
            d->t->enqueue( d->q );
            d->q = new Query( "alter table address_fields add message "
                              "integer", this );
            d->t->enqueue( d->q );
            d->q = new Query( "alter table date_fields add message "
                              "integer", this );
            d->t->enqueue( d->q );

            d->q = new Query( "update header_fields set message=m.id "
                              "from messages m where "
                              "header_fields.mailbox=m.mailbox and "
                              "header_fields.uid=m.uid", this );
            d->t->enqueue( d->q );
            d->q = new Query( "update address_fields set message=m.id "
                              "from messages m where "
                              "address_fields.mailbox=m.mailbox and "
                              "address_fields.uid=m.uid", this );
            d->t->enqueue( d->q );
            d->q = new Query( "update date_fields set message=m.id from "
                              "messages m where "
                              "date_fields.mailbox=m.mailbox and "
                              "date_fields.uid=m.uid", this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table header_fields alter message "
                              "set not null", this );
            d->t->enqueue( d->q );
            d->q = new Query( "alter table address_fields alter message "
                              "set not null", this );
            d->t->enqueue( d->q );
            d->q = new Query( "alter table date_fields alter message "
                              "set not null", this );
            d->t->enqueue( d->q );

            d->q = new Query( "drop index hf_mup", this );
            d->t->enqueue( d->q );
            d->q = new Query( "drop index af_mu", this );
            d->t->enqueue( d->q );
            d->q = new Query( "drop index df_mu", this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table header_fields drop mailbox", this );
            d->t->enqueue( d->q );
            d->q = new Query( "alter table address_fields drop mailbox", this );
            d->t->enqueue( d->q );
            d->q = new Query( "alter table date_fields drop mailbox", this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table header_fields drop uid", this );
            d->t->enqueue( d->q );
            d->q = new Query( "alter table address_fields drop uid", this );
            d->t->enqueue( d->q );
            d->q = new Query( "alter table date_fields drop uid", this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table header_fields add constraint "
                              "header_fields_message_fkey foreign key "
                              "(message,part) references "
                              "part_numbers(message, part) "
                              "on delete cascade", this );
            d->t->enqueue( d->q );
            d->q = new Query( "alter table address_fields add constraint "
                              "address_fields_message_fkey foreign key "
                              "(message,part) references "
                              "part_numbers(message, part) "
                              "on delete cascade", this );
            d->t->enqueue( d->q );
            d->q = new Query( "alter table date_fields add constraint "
                              "date_fields_message_fkey foreign key (message) "
                              "references messages(id) on delete cascade",
                              this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table header_fields add constraint "
                              "header_fields_message_key "
                              "unique(message,part,position,field)", this );
            d->t->enqueue( d->q );

            d->q = new Query( "create index af_mp on address_fields "
                              "(message,part)", this );
            d->t->enqueue( d->q );

            d->q = new Query( "alter table part_numbers drop mailbox", this );
            d->t->enqueue( d->q );
            d->q = new Query( "alter table part_numbers drop uid", this );
            d->t->enqueue( d->q );

            d->substate = 5;
            d->t->execute();
        }
    }

    if ( d->substate == 5 ) {
        if ( !d->q->done() )
            return false;

        describeStep( "4. Updating deliveries" );

        d->q = new Query( "alter table deliveries add message "
                          "integer", this );
        d->t->enqueue( d->q );

        d->q = new Query( "update deliveries set message=m.id "
                          "from messages m where "
                          "deliveries.mailbox=m.mailbox and "
                          "deliveries.uid=m.uid", this );
        d->t->enqueue( d->q );

        d->q = new Query( "alter table deliveries alter message "
                          "set not null", this );
        d->t->enqueue( d->q );

        d->q = new Query( "alter table deliveries drop mailbox", this );
        d->t->enqueue( d->q );

        d->q = new Query( "alter table deliveries drop uid", this );
        d->t->enqueue( d->q );

        d->q = new Query( "alter table deliveries add constraint "
                          "deliveries_message_fkey foreign key "
                          "(message) references messages(id) "
                          "on delete cascade", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table deliveries add constraint "
                          "deliveries_message_key unique(message)",
                          this );
        d->t->enqueue( d->q );

        d->substate = 6;
        d->t->execute();
    }

    if ( d->substate == 6 ) {
        if ( !d->q->done() )
            return false;

        describeStep( "5. Updating deleted_messages" );

        d->q = new Query( "alter table deleted_messages add message "
                          "integer", this );
        d->t->enqueue( d->q );

        d->q = new Query( "update deleted_messages set message=m.id "
                          "from messages m where "
                          "deleted_messages.mailbox=m.mailbox and "
                          "deleted_messages.uid=m.uid", this );
        d->t->enqueue( d->q );

        d->q = new Query( "alter table deleted_messages alter message "
                          "set not null", this );
        d->t->enqueue( d->q );

        d->q = new Query( "alter table deleted_messages add constraint "
                          "deleted_messages_mailbox_fkey foreign key "
                          "(mailbox) references mailboxes(id)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table deleted_messages add constraint "
                          "deleted_messages_message_fkey foreign key "
                          "(message) references messages(id)", this );
        d->t->enqueue( d->q );

        d->substate = 7;
        d->t->execute();
    }

    if ( d->substate == 7 ) {
        if ( !d->q->done() )
            return false;

        describeStep( "6. Dropping unnecessary tables and columns" );

        d->q = new Query( "alter table messages drop mailbox", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table messages drop uid", this );
        d->t->enqueue( d->q );

        d->q = new Query( "drop table modsequences", this );
        d->t->enqueue( d->q );
        d->q = new Query( "drop table view_messages", this );
        d->t->enqueue( d->q );

        d->q = new Query( "select d.relname::text,c.conname::text,"
                          "pg_get_constraintdef(c.oid) as condef "
                          "from pg_constraint c join pg_class d "
                          "on (c.conrelid=d.oid) where c.contype='u' "
                          "and d.relname='users'", this );
        d->t->enqueue( d->q );

        d->substate = 8;
        d->t->execute();
    }

    if ( d->substate == 8 ) {
        if ( !d->q->done() )
            return false;

        describeStep( "7. Miscellaneous changes" );

        if ( d->q->failed() || d->q->rows() == 0 ) {
            fail( "Couldn't fetch unique constraint on users", d->q );
            d->substate = 42;
        }
        else {
            Row * r = d->q->nextRow();

            d->q = new Query( "alter table users drop constraint " +
                              r->getString( "conname" ).quoted(), this );
            d->t->enqueue( d->q );
            d->q = new Query( "drop index u_l", this );
            d->t->enqueue( d->q );
            d->q = new Query( "create unique index u_l on users "
                              "(lower(login))", this );
            d->t->enqueue( d->q );

            d->substate = 9;
            d->t->execute();
        }
    }

    if ( d->substate == 9 ) {
        if ( !d->q->done() )
            return false;

        d->substate = 42;
    }

    if ( d->substate == 42 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Grant select,update on messages_id_seq. */

bool Schema::stepTo61()
{
    if ( d->substate == 0 ) {
        describeStep( "Granting privileges on messages_id_seq" );
        d->q = new Query( "grant select,update on messages_id_seq "
                          "to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Create a trigger on deleted_messages to remove the message. */

bool Schema::stepTo62()
{
    if ( d->substate == 0 ) {
        describeStep( "Adding deleted_messages_trigger." );
        d->q = new Query( "select lanname::text from pg_catalog.pg_language "
                          "where lanname='plpgsql'", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;

        if ( d->q->failed() || !d->q->hasResults() ) {
            fail( "PL/PgSQL is not available. Please re-run the "
                  "Archiveopteryx installer to enable PL/PgSQL." );
            d->substate = 42;
        }
        else {
            d->q =
                new Query( "create function delete_message() "
                           "returns trigger as $$"
                           "begin delete from mailbox_messages where "
                           "mailbox=NEW.mailbox and uid=NEW.uid; return NULL; "
                           "end;$$ language plpgsql security definer", this );
            d->t->enqueue( d->q );
            d->q =
                new Query( "create trigger deleted_messages_trigger "
                           "after insert on deleted_messages for each "
                           "row execute procedure delete_message()", this );
            d->t->enqueue( d->q );
            d->substate = 2;
            d->t->execute();
        }
    }

    if ( d->substate == 2 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Add deleted_messages.modseq. */

bool Schema::stepTo63()
{
    if ( d->substate == 0 ) {
        describeStep( "Adding deleted_messages.modseq" );
        d->q = new Query( "alter table deleted_messages add "
                          "modseq bigint", this );
        d->t->enqueue( d->q );
        d->q = new Query( "update deleted_messages set modseq=nextmodseq-1 "
                          "from mailboxes m where "
                          "deleted_messages.mailbox=m.id", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table deleted_messages alter modseq "
                          "set not null", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Make deleted_messages.message cascade on delete. */

bool Schema::stepTo64()
{
    if ( d->substate == 0 ) {
        describeStep( "Altering deleted_messages_message_fkey." );
        d->q = new Query( "alter table deleted_messages drop constraint "
                          "deleted_messages_message_fkey", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table deleted_messages add constraint "
                          "deleted_messages_message_fkey foreign key "
                          "(message) references messages(id) "
                          "on delete cascade", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Grant "update" on threads to aox, so that the threader can lock the
    table in exclusive mode.
*/

bool Schema::stepTo65()
{
    if ( d->substate == 0 ) {
        describeStep( "Granting update on threads." );
        d->q = new Query( "grant update on threads to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Change the unique constraint on threads to include "mailbox". */

bool Schema::stepTo66()
{
    if ( d->substate == 0 ) {
        describeStep( "Changing unique constraint on threads." );
        d->q = new Query( "select d.relname::text,c.conname::text,"
                          "pg_get_constraintdef(c.oid) as condef "
                          "from pg_constraint c join pg_class d "
                          "on (c.conrelid=d.oid) where c.contype='u' "
                          "and d.relname='threads'", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;

        if ( d->q->failed() || d->q->rows() == 0 ) {
            fail( "Couldn't fetch unique constraint on threads", d->q );
            d->substate = 42;
        }
        else {
            Row * r = d->q->nextRow();
            d->q = new Query( "alter table threads drop constraint " +
                              r->getString( "conname" ).quoted(), this );
            d->t->enqueue( d->q );
            d->q = new Query( "alter table threads add constraint "
                              "threads_subject_key unique "
                              "(mailbox,subject)", this );
            d->t->enqueue( d->q );
            d->substate = 2;
            d->t->execute();
        }
    }

    if ( d->substate == 2 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Create a couple of new indexes to make "aox vacuum" faster, and help
    to look for specific message-ids.
*/

bool Schema::stepTo67()
{
    if ( d->substate == 0 ) {
        describeStep( "Creating indexes to help foreign key/msgid lookups." );
        d->q = new Query( "create index mm_m on mailbox_messages(message)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "create index dm_m on deleted_messages(message)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "create index df_m on date_fields(message)", this );
        d->t->enqueue( d->q );
        d->q = new Query( "create index hf_msgid on header_fields(value) "
                          "where field=13", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Add a table to log connections. */

bool Schema::stepTo68()
{
    if ( d->substate == 0 ) {
        describeStep( "Add a table to log connections." );
        d->q = new Query(
            "create table connections (id serial primary key,userid integer "
            "references users(id),client varchar not null,mechanism varchar "
            "not null,authfailures integer not null,syntaxerrors integer not "
            "null,started_at timestamp with time zone not null,ended_at "
            "timestamp with time zone not null)", this
        );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Make subscriptions:(owner,mailbox) unique. */

bool Schema::stepTo69()
{
    if ( d->substate == 0 ) {
        describeStep( "Make subscriptions:(owner,mailbox) unique." );
        d->q = new Query(
            "delete from subscriptions where id in (select distinct "
            "s1.id from subscriptions s1 join subscriptions s2 "
            "using (owner,mailbox) where s1.id>s2.id)",
            this
        );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table subscriptions add "
                          "unique(owner,mailbox)", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Add a table to refer to mailboxes that sieve scripts depend on. */

bool Schema::stepTo70()
{
    if ( d->substate == 0 ) {
        describeStep( "Add a table to record sieve target mailboxes." );
        d->q = new Query(
            "create table fileinto_targets (id serial primary key,"
            "script integer not null references scripts(id) on delete "
            "cascade, mailbox integer not null references mailboxes(id),"
            "unique(script, mailbox))", this
        );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Grant some missing privileges. Sigh. */

bool Schema::stepTo71()
{
    if ( d->substate == 0 ) {
        describeStep( "Granting privileges on connections/fileinto_targets." );
        d->q = new Query( "grant insert,delete on connections to " + d->dbuser,
                          this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,update on connections_id_seq to " +
                          d->dbuser, this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,insert,delete on fileinto_targets "
                          "to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->q = new Query( "grant select,update on fileinto_targets_id_seq "
                          "to " + d->dbuser, this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Fix incorrect 2.09 EXPUNGEs. */

bool Schema::stepTo72()
{
    if ( d->substate == 0 ) {
        describeStep( "Reverting incorrect 2.09 EXPUNGEs." );
        d->q = new Query(
            "select a.mailbox,a.uid,a.message,m.name "
            "from deleted_messages a "
            "join mailboxes m on (a.mailbox=m.id) "
            "where deleted_by<>m.owner "
            "order by m.name, a.uid", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
        fprintf( stderr,
                 "\t- Looking for messages deleted by other users.\n" );
    }

    if ( d->q ) {
        if ( !d->q->done() )
            return false;
        else if ( !d->row )
            fprintf( stderr,
                     "\t- Found %d messages.\n", d->q->rows() );
    }

    while ( d->row || d->q->hasResults() ) {
        if ( !d->row )
            d->row = d->q->nextRow();

        uint mailbox = d->row->getInt( "mailbox" );
        uint uid = d->row->getInt( "uid" );

        if ( mailbox != d->lastMailbox && !d->quid ) {
            if ( d->lastMailbox ) {
                Query * q = new Query(
                    "update mailboxes set uidnext=uidnext+$2, "
                    "nextmodseq=nextmodseq+1 where id=$1", this
                    );
                q->bind( 1, d->lastMailbox );
                q->bind( 2, d->count );
                d->t->enqueue( q );
            }

            fprintf( stderr,
                     "\t  - Processing mailbox %s.\n",
                     d->row->getUString( "name" ).ascii().cstr() );
            d->lastMailbox = mailbox;
            d->count = 0;

            d->quid = new Query(
                "select uidnext,nextmodseq from mailboxes "
                "where id=$1 for update", this
                );
            d->quid->bind( 1, d->lastMailbox );
            d->t->enqueue( d->quid );
            d->t->execute();
        }

        if ( d->quid ) {
            if ( !d->quid->done() )
                return false;

            Row * r = d->quid->nextRow();
            d->uidnext = r->getInt( "uidnext" );
            d->nextmodseq = r->getBigint( "nextmodseq" );
            d->quid = 0;
        }

        Query * q = new Query(
            "delete from deleted_messages where "
            "mailbox=$1 and uid=$2", this );
        q->bind( 1, mailbox );
        q->bind( 2, uid );
        d->t->enqueue( q );

        q = new Query(
            "insert into mailbox_messages "
            "(mailbox,uid,message,modseq,idate) "
            "values ($1,$2,$3,$4,extract(epoch from current_timestamp))",
            this );
        q->bind( 1, mailbox );
        q->bind( 2, d->uidnext+d->count );
        q->bind( 3, d->row->getInt( "message" ) );
        q->bind( 4, d->nextmodseq );
        d->t->enqueue( q );

        d->count++;
        d->row = 0;
        d->quid = 0;
        d->undel = 0;
    }

    if ( d->substate == 1 ) {
        d->q = new Query(
            "select a.mailbox,a.uid,a.message,m.name "
            "from deleted_messages a "
            "join mailboxes m on (a.mailbox=m.id) "
            "where (reason,deleted_by,deleted_at) in (select "
            "reason,deleted_by,deleted_at from deleted_messages "
            "group by reason,deleted_by,deleted_at having "
            "count(distinct mailbox) > 1) "
            "order by m.name,a.uid", this
        );
        d->t->enqueue( d->q );
        d->substate = 2;
        d->t->execute();
        fprintf( stderr,
                 "\t- Looking for deletes affecting more than one mailbox.\n");
        return false;
    }

    if ( d->substate == 2 ) {
        if ( d->lastMailbox ) {
            Query * q = new Query(
                "update mailboxes set uidnext=uidnext+$2, "
                "nextmodseq=nextmodseq+1 where id=$1", this );
            q->bind( 1, d->lastMailbox );
            q->bind( 2, d->count );
            d->t->enqueue( q );
        }
    }

    return true;
}


/*! Split connections.client into address/port. */

bool Schema::stepTo73()
{
    if ( d->substate == 0 ) {
        describeStep( "Split connections.client into address/port." );
        d->q = new Query( "delete from connections", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table connections add address "
                          "inet not null", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table connections add port "
                          "integer not null", this );
        d->t->enqueue( d->q );
        d->q = new Query( "alter table connections drop client", this );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
    }

    return true;
}


/*! Make bodyparts.hash non-unique. */

bool Schema::stepTo74()
{
    if ( d->substate == 0 ) {
        describeStep( "Allow two bodyparts to have the same MD5 hash." );
        d->substate = 1;
        d->t->enqueue( new Query( "alter table bodyparts "
                                  "drop constraint bodyparts_hash_key", 0 ) );
        d->t->execute();
    }

    return true;
}


/*! ...but don't make it non-indexed. */

bool Schema::stepTo75()
{
    if ( d->substate == 0 ) {
        describeStep( "Create an index on bodyparts.hash" );
        d->substate = 1;
        d->t->enqueue( new Query( "create index b_h on bodyparts(hash)", 0 ) );
        d->t->execute();
    }

    return true;
}


/*! Add an index on d_m(mailbox,modseq) plus a couple of cleanups. */

bool Schema::stepTo76()
{
    if ( d->substate == 0 ) {
        describeStep( "Miscellaneous cleanups." );
        d->q = new Query( "select 42 as answer from pg_indexes "
                          "where schemaname=$1 and indexname='dm_mm'", this );
        d->q->bind( 1, Configuration::text( Configuration::DbSchema ) );
        d->t->enqueue( d->q );
        d->substate = 1;
        d->t->enqueue( new Query( "delete from thread_members", 0 ) );
        d->t->enqueue( new Query( "delete from threads", 0 ) );
        d->t->enqueue( new Query( "alter table deliveries drop tried_at", 0 ) );
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        if ( !d->q->hasResults() ) {
            d->t->enqueue( new Query( "create index dm_mm on deleted_messages "
                                      "(mailbox,modseq)", 0 ) );
            d->t->execute();
        }
        d->substate = 2;
    }

    return true;
}


/*! Add an ldapdn column to users (if it doesn't already exist).

    3.0.3/schema.pg was mistakenly released with mailstore.revision=76,
    but with all the changes from schema #77. So fresh installations of
    3.0.3 will later try to execute stepTo77(), and we need to silently
    succeed if there's nothing to do.
*/

bool Schema::stepTo77()
{
    if ( d->substate == 0 ) {
        describeStep( "Add an LDAP-DN column to users." );
        d->substate = 1;
        d->q = new Query( "select 42 as answer "
                          "from pg_attribute a "
                          "join pg_class c on (a.attrelid=c.oid) "
                          "join pg_namespace n on (c.relnamespace=n.oid) "
                          "where c.relname='users' and a.attname='ldapdn' and "
                          "n.nspname=$1", this );
        d->q->bind( 1, Configuration::text( Configuration::DbSchema ) );
        d->t->enqueue( d->q );
        d->t->execute();
    }

    if ( d->substate == 1 ) {
        if ( !d->q->done() )
            return false;
        if ( !d->q->hasResults() ) {
            d->t->enqueue( new Query( "alter table users add ldapdn text", 0 ) );
            d->t->execute();
        }
        d->substate = 2;
    }

    return true;
}


/*! Move mailbox_messages.idate to messages.idate. */

bool Schema::stepTo78()
{
    if ( d->substate == 0 ) {
        describeStep( "Move mailbox_messages.idate to messages." );
        d->substate = 1;
        d->t->enqueue( new Query( "alter table messages add idate int", 0 ) );
        d->t->enqueue( new Query( "update messages set idate=mm.idate "
                                  "from mailbox_messages mm where "
                                  "mm.message=messages.id", 0 ) );
        d->t->enqueue( new Query( "update messages set idate=0 "
                                  "where idate is null", 0 ) );
        d->t->enqueue( new Query( "alter table messages alter idate "
                                  "set not null", 0 ) );
        d->t->enqueue( new Query( "alter table mailbox_messages "
                                  "drop idate", 0 ) );
        d->t->execute();
    }

    return true;
}


/*! Create thread_indexes. */

bool Schema::stepTo79()
{
    if ( d->substate == 0 ) {
        describeStep( "Create thread_indexes." );
        d->substate = 1;
        d->t->enqueue( new Query( "create table thread_indexes "
                                  "(message integer not null references "
                                  "messages(id), thread_index text)", 0 ) );
        d->t->enqueue( new Query( "create index ti_outlook_hack on "
                                  "thread_indexes(thread_index)", 0 ) );
        d->t->execute();
    }

    return true;
}


/*! Add "on delete cascade" to thread_indexes.message. */

bool Schema::stepTo80()
{
    if ( d->substate == 0 ) {
        describeStep( "Add 'on delete cascade' to thread_indexes.message." );
        d->substate = 1;
        d->t->enqueue( new Query( "alter table thread_indexes drop constraint "
                                  "thread_indexes_message_fkey", 0 ) );
        d->t->enqueue( new Query( "alter table thread_indexes add constraint "
                                  "thread_indexes_message_fkey foreign "
                                  "key(message) references messages(id) "
                                  "on delete cascade", 0 ) );
        d->t->execute();
    }

    return true;
}


/*! Fixes mailbox ownership and installs a trigger to keep it right.

    aoximport and perhaps other code could create mailboxes such as
    /users/foo/stuff without knowing that /users/foo is someone's
    home, and therefore the new mailbox should be owned by foo.
*/

bool Schema::stepTo81()
{
    describeStep( "Add a trigger to ensure that users own their mailboxes." );

    // fix old rows (e.g. created by aoximport)
    d->t->enqueue(
        new Query( "update mailboxes set owner=u.id "
                   "from users u join namespaces n on (u.parentspace=n.id) "
                   "where mailboxes.name like n.name||'/'||u.login||'/%' and "
                   "(owner is null or owner!=u.id)", 0 ) );

    // then make sure that new rows are set up correctly
    d->t->enqueue(
        new Query( "create function set_mailbox_owner() "
                   "returns trigger as $$"
                   "begin "
                   "if new.owner is null then "
                   // I've no idea whether this is correct syntax or will work
                   "new.owner=coalesce("
                   "select u.id from users u "
                   "join namespaces n on (u.parentspace=n.id) "
                   "where new.name like n.name||'/'||u.login||'/%' "
                   "or new.name = n.name||'/'||u.login', null) "
                   "end if; "
                   "return new;"
                   "end;$$ language pgsql security definer", 0 ) );
    d->t->enqueue(
        new Query( "create trigger mailbox_owner_trigger "
                   "before insert on mailboxes for each "
                   "row execute procedure set_mailbox_owner()", 0 ) );

    return true;
}


/*! Installs a trigger to prevent deleting mailboxes that have to be
    there for one reason or another.
  
    What we really want is to delete the mail in the mailbox when the
    mailbox is deleted, but to do that we need (at a minimum) the
    responsible user. So what we must do is prevent the deletion, and
    in the application code we must delete the messages before
    deleting the mailbox.

    However, if any bad mailboxes already exist (as they do, not sure
    why) then aox upgrade schema can delete any mail them. aox upgrade
    schema knows who ran it.
*/

bool Schema::stepTo82()
{
    describeStep( "Add a trigger to prevent deleting nonempty mailboxes." );

    // delete any mail we can't reach (but permit undeleting)
    d->t->enqueue(
        new Query( "insert into deleted_messages "
                   "(mailbox, uid, message, modseq, deleted_by, reason) "
                   "select mm.mailbox, mm.uid, mm.message, mb.nextmodseq, "
                   "current_timestamp, "
                   "'aox upgrade schema found nonempty deleted mailbox' "
                   "from mailbox_messages mm "
                   "join mailboxes mb on (mm.mailbox=mb.id) "
                   "where mb.deleted='t'", 0 ) );

    // and recover any deleted mailboxes we might have deleted in the past
    d->t->enqueue(
        new Query( "update mailboxes set deleted='f' "
                   "where deleted='f' and "
                   "(id in (select mailbox from aliases) or"
                   " id in (select fileinto_targets))", 0 ) );

    // install a trigger to make sure necessary mailboxes don't disappear
    d->t->enqueue(
        new Query( "create function check_mailbox_update() "
                   "returns trigger as $$"
                   "begin "
                   "notify mailboxes_updated; "
                   "if new.deleted='t' and old.deleted='f' then "
                   "if "// there's mail in the mailbox
                   "raise exception '% is not empty', NEW.name;"
                   "end if; "
                   "if "// any aliases.mailbox point to it
                   "raise exception '% is tied to alias %', NEW.name;"
                   "end if; "
                   "if "// any fileinto_targets.mailbox point to it
                   "raise exception '% is referred to sieve fileinto', NEW.name;"
                   "end if; "
                   "end if; "
                   "return new;"
                   "end;$$ language pgsql security definer", 0 ) );
    d->t->enqueue(
        new Query( "create trigger mailbox_update_trigger "
                   "before update on mailboxes for each "
                   "row execute procedure check_mailbox_update()", 0 ) );

    return true;

}


/*! Installs one/two trigger(s) to ensure that a mailbox' nextmodseq
    increases when necessary.

    We could push it even further... insert into flags, annotations
    and deleted_messages could set the modseq on deleted_messages /
    mailbox_messages to mailboxes.nextmodseq. Then we'd need to select
    the mailbox for update before updating it, but not care about
    modseq in client code.
*/

bool Schema::stepTo83()
{
    describeStep( "Add triggers to ensure that modseq increases as it ought to." );

    d->t->enqueue(
        new Query( "create function increase_nextmodseq() "
                   "returns trigger as $$"
                   "begin "
                   "update mailboxes "
                   "set nextmodseq=new.modseq+1 "
                   "where id=new.mailbox and nextmodseq<=new.modseq;"
                   "return null;"
                   "end;$$ language pgsql security definer", 0 ) );
    d->t->enqueue(
        new Query( "create trigger mailbox_messages_update_trigger "
                   "after update or insert on mailbox_messages "
                   "for each row execute procedure increase_nextmodseq()", 0 ) );
    d->t->enqueue(
        new Query( "create trigger deleted_messages_update_trigger "
                   "after update or insert on mailbox_messages "
                   "for each row execute procedure increase_nextmodseq()", 0 ) );

    // wouldn't this be better as a "statement after" that uses
    // max(new.modseq) group by mailbox? is that even possible? if it
    // isn't, then maybe this is too expensive to do.

    return true;
}
