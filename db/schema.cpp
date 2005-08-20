// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "schema.h"

#include "log.h"
#include "query.h"
#include "transaction.h"
#include "stringlist.h"
#include "allocator.h"
#include "dict.h"
#include "md5.h"


int currentRevision = 10;


class SchemaData
    : public Garbage
{
public:
    SchemaData()
        : l( new Log( Log::Database ) ),
          state( 0 ), substate( 0 ), revision( 0 ),
          lock( 0 ), seq( 0 ), update( 0 ), q( 0 ), t( 0 ),
          result( 0 ), upgrade( false )
    {}

    Log *l;
    int state;
    int substate;
    int revision;
    Query *lock, *seq, *update, *q;
    Transaction *t;
    Query *result;
    bool upgrade;
};


/*! \class Schema schema.h
    This class represents the Oryx database schema.

    The static check() function verifies during server startup that the
    running server is compatible with the existing schema.
*/


/*! Creates a new Schema object to check that the existing schema is one
    that the running server understands. If \a upgrade is true (which it
    is not, by default) and the schema is too old, it will be upgraded.
    The \a owner will be notified of progress via the Query returned by
    result().
*/

Schema::Schema( EventHandler * owner, bool upgrade )
    : d( new SchemaData )
{
    d->result = new Query( owner );
    d->upgrade = upgrade;
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


/*! Checks or upgrades the schema as required. */

void Schema::execute()
{
    if ( d->state == 0 ) {
        d->lock =
            new Query( "select revision from mailstore for update", this );
        d->t->enqueue( d->lock );
        d->t->execute();
        d->state = 1;
    }

    if ( d->state == 1 ) {
        if ( !d->lock->done() )
            return;

        Row *r = d->lock->nextRow();
        if ( r )
            d->revision = r->getInt( "revision" );

        if ( !r || d->lock->failed() ) {
            String s( "Bad database: Couldn't query the mailstore table." );
            d->l->log( s, Log::Disaster );
            d->revision = currentRevision;
            d->result->setError( s );
            d->t->commit();
            d->state = 7;
        }
        else if ( d->revision == currentRevision ) {
            d->result->setState( Query::Completed );
            d->t->commit();
            d->state = 7;
        }
        else if ( d->upgrade && d->revision < currentRevision ) {
            d->l->log( "Updating schema from revision " +
                       fn( d->revision ) + " to revision " +
                       fn( currentRevision ) );
            d->state = 2;
        }
        else {
            String s( "The existing schema (revision #" );
            s.append( fn( d->revision ) );
            s.append( ") is " );
            if ( d->revision < currentRevision )
                s.append( "older" );
            else
                s.append( "newer" );
            s.append( " than this server (version " );
            s.append( Configuration::compiledIn( Configuration::Version ) );
            s.append( ") expected (revision #" );
            s.append( fn( currentRevision ) );
            s.append( "). Please " );
            if ( d->revision < currentRevision )
                s.append( "run 'ms upgrade schema'" );
            else
                s.append( "upgrade" );
            s.append( " or contact support." );

            d->l->log( s, Log::Disaster );
            d->revision = currentRevision;
            d->result->setError( s );
            d->t->commit();
            d->state = 7;
        }
    }

    while ( d->revision < currentRevision ) {
        if ( d->state == 2 ) {
            d->seq =
                new Query( "select nextval('revisions')::integer as seq",
                           this );
            d->t->enqueue( d->seq );
            d->t->execute();
            d->state = 3;
        }

        if ( d->state == 3 ) {
            if ( !d->seq->done() )
                return;

            int gap = d->seq->nextRow()->getInt( "seq" ) - d->revision;
            if ( gap > 1 ) {
                String s( "Can't upgrade schema because an earlier "
                          "attempt to do so failed." );
                d->l->log( s, Log::Disaster );
                d->revision = currentRevision;
                d->result->setError( s );
                d->t->commit();
                d->state = 7;
                break;
            }
            d->state = 4;
        }

        if ( d->state == 4 ) {
            if ( d->revision == 1 ) {
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
                        return;
                    d->l->log( "Done.", Log::Debug );
                    d->substate = 0;
                }
            }

            if ( d->revision == 2 ) {
                if ( d->substate == 0 ) {
                    d->l->log( "Merging bodyparts and binary_parts", Log::Debug );
                    d->q = new Query( "alter table bodyparts add hash text",
                                   this );
                    d->t->enqueue( d->q );
                    d->q = new Query( "alter table bodyparts add data bytea",
                                   this );
                    d->t->enqueue( d->q );
                    d->q = new Query( "alter table bodyparts add text2 text",
                                   this );
                    d->t->enqueue( d->q );
                    d->q = new Query( "update bodyparts set data=b.data from "
                                   "binary_parts b where id=b.bodypart",
                                   this );
                    d->t->enqueue( d->q );
                    d->q = new Query( "declare parts cursor for "
                                   "select id,text,data from bodyparts",
                                   this );
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
                        return;

                    if ( d->q->rows() != 0 ) {
                        d->q = new Query( "fetch 512 from parts", this );
                        d->t->enqueue( d->q );
                        d->t->execute();
                        return;
                    }
                    else {
                        d->substate = 2;
                        d->t->enqueue( new Query( "close parts", this ) );
                    }
                }

                if ( d->substate == 2 ) {
                    d->q = new Query( "alter table bodyparts drop text", this );
                    d->t->enqueue( d->q );
                    d->q = new Query( "alter table bodyparts rename text2 to text",
                                   this );
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
                        return;

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
                                           "bodypart=$1 where bodypart=$2",
                                           this );
                            u->bind( 1, *old );
                            u->bind( 2, id );
                            d->t->enqueue( u );
                        }
                        else {
                            uint * tmp
                                = (uint*)Allocator::alloc( sizeof(uint) );
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
                    d->q = new Query( "alter table bodyparts add unique(hash)",
                                   this );
                    d->t->enqueue( d->q );
                    d->t->execute();
                    d->substate = 4;
                }

                if ( d->substate == 4 ) {
                    if ( !d->q->done() )
                        return;
                    d->l->log( "Done.", Log::Debug );
                    d->substate = 0;
                }
            }

            if ( d->revision == 3 ) {
                if ( d->substate == 0 ) {
                    d->l->log( "Creating flags from messages/extra_flags.",
                            Log::Debug );
                    d->q = new Query( "alter table extra_flags rename to flags",
                                   this );
                    d->t->enqueue( d->q );
                    d->q = new Query( "insert into flag_names (name) values ($1)",
                                   this );
                    d->q->bind( 1, "\\Deleted" );
                    d->t->enqueue( d->q );
                    d->q = new Query( "insert into flag_names (name) values ($1)",
                                   this );
                    d->q->bind( 1, "\\Answered" );
                    d->t->enqueue( d->q );
                    d->q = new Query( "insert into flag_names (name) values ($1)",
                                   this );
                    d->q->bind( 1, "\\Flagged" );
                    d->t->enqueue( d->q );
                    d->q = new Query( "insert into flag_names (name) values ($1)",
                                   this );
                    d->q->bind( 1, "\\Draft" );
                    d->t->enqueue( d->q );
                    d->q = new Query( "insert into flag_names (name) values ($1)",
                                   this );
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
                        return;
                    d->l->log( "Done.", Log::Debug );
                    d->substate = 0;
                }
            }

            if ( d->revision == 4 ) {
                if ( d->substate == 0 ) {
                    d->l->log( "Adding hf_mup, af_mu, fl_mu indices.",
                            Log::Debug );
                    d->q = new Query( "create index hf_mup on "
                                   "header_fields (mailbox,uid,part)", this );
                    d->t->enqueue( d->q );
                    d->q = new Query( "create index af_mu on "
                                   "address_fields (mailbox,uid)", this );
                    d->t->enqueue( d->q );
                    d->q = new Query( "create index fl_mu on "
                                   "flags (mailbox,uid)", this );
                    d->t->enqueue( d->q );
                    d->t->execute();
                    d->substate = 1;
                }

                if ( d->substate == 1 ) {
                    if ( !d->q->done() )
                        return;
                    d->l->log( "Done.", Log::Debug );
                    d->substate = 0;
                }
            }

            if ( d->revision == 5 ) {
                if ( d->substate == 0 ) {
                    d->l->log( "Moving bytes/lines to part_numbers.",
                            Log::Debug );
                    d->q = new Query( "alter table part_numbers add "
                                   "bytes integer", this );
                    d->t->enqueue( d->q );
                    d->q = new Query( "alter table part_numbers add "
                                   "lines integer", this );
                    d->t->enqueue( d->q );
                    d->q = new Query( "update part_numbers set "
                                   "bytes=bodyparts.bytes,"
                                   "lines=bodyparts.lines from "
                                   "bodyparts where "
                                   "part_numbers.bodypart=bodyparts.id",
                                   this );
                    d->t->enqueue( d->q );
                    d->q = new Query( "alter table bodyparts drop lines",
                                   this );
                    d->t->enqueue( d->q );
                    d->t->execute();
                    d->substate = 1;
                }

                if ( d->substate == 1 ) {
                    if ( !d->q->done() )
                        return;
                    d->l->log( "Done.", Log::Debug );
                    d->substate = 0;
                }
            }

            if ( d->revision == 6 ) {
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
                                   "from header_fields",
                                   this );
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

                        u = new Query( "alter sequence hf_pos restart with 1",
                                       this );
                        d->t->enqueue( u );
                    }

                    if ( !d->q->done() )
                        return;

                    if ( d->q->rows() != 0 ) {
                        d->q = new Query( "fetch 512 from groups", this );
                        d->t->enqueue( d->q );
                        d->t->execute();
                        return;
                    }
                    else {
                        d->t->enqueue( new Query( "close groups", this ) );
                        d->q = new Query( "alter table header_fields add unique "
                                       "(mailbox,uid,part,position,field)",
                                       this );
                        d->t->enqueue( d->q );
                        d->t->execute();
                        d->substate = 2;
                    }
                }

                if ( d->substate == 2 ) {
                    if ( !d->q->done() )
                        return;
                    d->l->log( "Done.", Log::Debug );
                    d->substate = 0;
                }
            }

            if ( d->revision == 7 ) {
                if ( d->substate == 0 ) {
                    d->l->log( "Making address_fields refer to header_fields.",
                            Log::Debug );
                    d->q = new Query( "delete from address_fields", this );
                    d->t->enqueue( d->q );
                    d->q = new Query( "alter table address_fields drop field",
                                   this );
                    d->t->enqueue( d->q );
                    d->q = new Query( "alter table address_fields add "
                                   "part text", this );
                    d->t->enqueue( d->q );
                    d->q = new Query( "alter table address_fields alter "
                                   "part set not null", this );
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
                    d->q = new Query( "alter table address_fields alter "
                                   "field set not null", this );
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
                        return;
                    d->l->log( "Done.", Log::Debug );
                    d->substate = 0;
                }
            }

            if ( d->revision == 8 ) {
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
                        return;
                    d->l->log( "Done.", Log::Debug );
                    d->substate = 0;
                }
            }

            if ( d->revision == 9 ) {
                if ( d->substate == 0 ) {
                    d->l->log( "Altering mailboxes_owner_fkey.", Log::Debug );
                    d->q = new Query( "select version()", this );
                    d->t->enqueue( d->q );
                    d->t->execute();
                    d->substate = 1;
                }

                if ( d->substate == 1 ) {
                    if ( !d->q->done() )
                        return;

                    String constraint = "mailboxes_owner_fkey";

                    Row * r = d->q->nextRow();
                    if ( r ) {
                        String version = r->getString( "version" );
                        if ( version.startsWith( "PostgreSQL 7" ) )
                            constraint = "$1";
                    }

                    d->q = new Query( "alter table mailboxes drop constraint "
                                      "\"" + constraint + "\"", this );
                    d->t->enqueue( d->q );
                    d->q = new Query( "alter table mailboxes add constraint "
                                      "mailboxes_owner_fkey foreign key "
                                      "(owner) references users(id) "
                                      "on delete cascade", this );
                    d->t->enqueue( d->q );
                    d->t->execute();
                    d->substate = 2;
                }

                if ( d->substate == 2 ) {
                    if ( !d->q->done() )
                        return;
                    d->l->log( "Done.", Log::Debug );
                    d->substate = 0;
                }
            }

            // Remember to update currentRevision when you add something
            // here.

            d->state = 5;
        }

        if ( d->state == 5 ) {
            d->update =
                new Query( "update mailstore set revision=revision+1",
                           this );
            d->t->enqueue( d->update );
            d->t->execute();
            d->state = 6;
        }

        if ( d->state == 6 ) {
            if ( !d->update->done() )
                return;

            d->state = 2;
            d->revision++;

            if ( d->revision == currentRevision ) {
                d->t->commit();
                d->state = 8;
                break;
            }
        }
    }

    if ( d->state == 7 || d->state == 8 ) {
        if ( !d->t->done() )
            return;

        if ( d->t->failed() && !d->result->failed() ) {
            String s( "The schema " );
            if ( d->upgrade )
                s.append( "could not be upgraded to revision " +
                          fn( currentRevision ) );
            else
                s.append( "validation" );
            s.append( " failed." );

            d->l->log( s, Log::Disaster );
            d->result->setError( s );
        }
        else if ( d->state == 8 ) {
            d->result->setState( Query::Completed );
            d->l->log( "Schema updated to revision " + fn( currentRevision ) );
        }
        d->state = 9;
    }

    if ( d->state == 9 ) {
        d->state = 42;
        d->result->notify();
    }
}


/*! This function is responsible for checking that the running server is
    compatible with the existing database schema, and to notify \a owner
    when the verification is complete.

    If the schema is not compatible, a disaster is logged.

    The function expects to be called from ::main(), and should be the
    first database transaction.
*/

void Schema::check( EventHandler * owner )
{
    Schema * s = new Schema( owner );
    owner->waitFor( s->result() );
    s->execute();
}
