// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "configuration.h"
#include "addresscache.h"
#include "transaction.h"
#include "logclient.h"
#include "allocator.h"
#include "occlient.h"
#include "mailbox.h"
#include "address.h"
#include "scope.h"
#include "event.h"
#include "query.h"
#include "user.h"
#include "loop.h"
#include "dict.h"
#include "md5.h"
#include "log.h"

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>


static int status;
static Transaction * transaction;
static Query * query;
static const char * name;


/*! \nodoc */


static int currentRevision = 9;


class UpdateSchema
    : public EventHandler
{
private:
    int state;
    int substate;
    int revision;
    Transaction *t;
    Query *lock, *seq, *update, *q;
    Log *l;

public:
    UpdateSchema()
        : state( 0 ), substate( 0 ), revision( 0 ),
          t( new Transaction( this ) ),
          l( new Log( Log::Database ) )
    {}

    Transaction *transaction() const { return t; }
    void execute();
};


void UpdateSchema::execute() {
    // Find and lock the current schema revision.
    if ( state == 0 ) {
        lock = new Query( "select revision from mailstore for update",
                          this );
        t->enqueue( lock );
        t->execute();
        state = 1;
    }

    if ( state == 1 ) {
        if ( !lock->done() )
            return;

        Row *r = lock->nextRow();
        if ( lock->failed() || !r ) {
            l->log( "Database inconsistent: "
                    "Couldn't query the mailstore table.",
                    Log::Disaster );
            return;
        }

        revision = r->getInt( "revision" );
        if ( revision == currentRevision ) {
            state = 7;
            t->commit();
        }
        else if ( revision > currentRevision ) {
            l->log( "The schema is newer than this server expected. "
                    "Schema revision " + fn( revision ) +
                    ", supported revision " + fn( currentRevision ) +
                    ", server version " +
                    Configuration::compiledIn( Configuration::Version ) +
                    ". Please upgrade or consult support.",
                    Log::Disaster );
            state = 9;
            return;
        }
        else {
            l->log( "Updating schema from revision " + fn( revision ) +
                    " to revision " + fn( currentRevision ) );
            state = 2;
        }
    }

    // Perform successive updates towards the current revision.
    while ( revision < currentRevision ) {
        if ( state == 2 ) {
            seq = new Query( "select nextval('revisions')::integer as seq",
                             this );
            t->enqueue( seq );
            t->execute();
            state = 3;
        }
        if ( state == 3 ) {
            if ( !seq->done() )
                return;
            int gap = seq->nextRow()->getInt( "seq" ) - revision;
            if ( gap > 1 ) {
                l->log( "Can't update because an earlier schema update failed.",
                        Log::Disaster );
                state = 9;
                break;
            }
            state = 4;
        }
        if ( state == 4 ) {
            if ( revision == 1 ) {
                if ( substate == 0 ) {
                    l->log( "Changing users.login/secret to text", Log::Debug );
                    q = new Query( "alter table users add login2 text", this );
                    t->enqueue( q );
                    q = new Query( "update users set login2=login", this );
                    t->enqueue( q );
                    q = new Query( "alter table users drop login", this );
                    t->enqueue( q );
                    q = new Query( "alter table users rename login2 to login",
                                   this );
                    t->enqueue( q );
                    q = new Query( "alter table users add unique(login)",
                                   this );
                    t->enqueue( q );
                    q = new Query( "alter table users add secret2 text", this );
                    t->enqueue( q );
                    q = new Query( "update users set secret2=secret", this );
                    t->enqueue( q );
                    q = new Query( "alter table users drop secret", this );
                    t->enqueue( q );
                    q = new Query( "alter table users rename secret2 to secret",
                                   this );
                    t->enqueue( q );
                    t->execute();
                    substate = 1;
                }

                if ( substate == 1 ) {
                    if ( !q->done() )
                        return;
                    l->log( "Done.", Log::Debug );
                    substate = 0;
                }
            }

            if ( revision == 2 ) {
                if ( substate == 0 ) {
                    l->log( "Merging bodyparts and binary_parts", Log::Debug );
                    q = new Query( "alter table bodyparts add hash text",
                                   this );
                    t->enqueue( q );
                    q = new Query( "alter table bodyparts add data bytea",
                                   this );
                    t->enqueue( q );
                    q = new Query( "alter table bodyparts add text2 text",
                                   this );
                    t->enqueue( q );
                    q = new Query( "update bodyparts set data=b.data from "
                                   "binary_parts b where id=b.bodypart",
                                   this );
                    t->enqueue( q );
                    q = new Query( "declare parts cursor for "
                                   "select id,text,data from bodyparts",
                                   this );
                    t->enqueue( q );
                    q = new Query( "fetch 512 from parts", this );
                    t->enqueue( q );
                    t->execute();
                    substate = 1;
                }

                if ( substate == 1 ) {
                    while ( q->hasResults() ) {
                        Row *r = q->nextRow();
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
                        t->enqueue( u );
                    }

                    if ( !q->done() )
                        return;

                    if ( q->rows() != 0 ) {
                        q = new Query( "fetch 512 from parts", this );
                        t->enqueue( q );
                        t->execute();
                        return;
                    }
                    else {
                        substate = 2;
                        t->enqueue( new Query( "close parts", this ) );
                    }
                }

                if ( substate == 2 ) {
                    q = new Query( "alter table bodyparts drop text", this );
                    t->enqueue( q );
                    q = new Query( "alter table bodyparts rename text2 to text",
                                   this );
                    t->enqueue( q );
                    q = new Query( "select id,hash from bodyparts where hash in "
                                   "(select hash from bodyparts group by hash"
                                   " having count(*) > 1)", this );
                    t->enqueue( q );
                    t->execute();
                    substate = 3;
                }

                if ( substate == 3 ) {
                    if ( !q->done() )
                        return;

                    StringList ids;
                    Dict< uint > hashes;

                    while ( q->hasResults() ) {
                        Row *r = q->nextRow();
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
                            t->enqueue( u );
                        }
                        else {
                            uint * tmp 
                                = (uint*)Allocator::alloc( sizeof(uint) );
                            *tmp = id;
                            hashes.insert( hash, tmp );
                        }
                    }

                    if ( !ids.isEmpty() ) {
                        q = new Query( "delete from bodyparts where id in "
                                       "(" + ids.join(",") + ")", this );
                        t->enqueue( q );
                    }
                    q = new Query( "drop table binary_parts", this );
                    t->enqueue( q );
                    q = new Query( "alter table bodyparts add unique(hash)",
                                   this );
                    t->enqueue( q );
                    t->execute();
                    substate = 4;
                }

                if ( substate == 4 ) {
                    if ( !q->done() )
                        return;
                    l->log( "Done.", Log::Debug );
                    substate = 0;
                }
            }

            if ( revision == 3 ) {
                if ( substate == 0 ) {
                    l->log( "Creating flags from messages/extra_flags.",
                            Log::Debug );
                    q = new Query( "alter table extra_flags rename to flags",
                                   this );
                    t->enqueue( q );
                    q = new Query( "insert into flag_names (name) values ($1)",
                                   this );
                    q->bind( 1, "\\Deleted" );
                    t->enqueue( q );
                    q = new Query( "insert into flag_names (name) values ($1)",
                                   this );
                    q->bind( 1, "\\Answered" );
                    t->enqueue( q );
                    q = new Query( "insert into flag_names (name) values ($1)",
                                   this );
                    q->bind( 1, "\\Flagged" );
                    t->enqueue( q );
                    q = new Query( "insert into flag_names (name) values ($1)",
                                   this );
                    q->bind( 1, "\\Draft" );
                    t->enqueue( q );
                    q = new Query( "insert into flag_names (name) values ($1)",
                                   this );
                    q->bind( 1, "\\Seen" );
                    t->enqueue( q );
                    q = new Query( "insert into flags (mailbox,uid,flag) "
                                   "select mailbox,uid,"
                                   "(select id from flag_names"
                                   " where name='\\Deleted') from messages "
                                   "where deleted", this );
                    t->enqueue( q );
                    q = new Query( "insert into flags (mailbox,uid,flag) "
                                   "select mailbox,uid,"
                                   "(select id from flag_names"
                                   " where name='\\Answered') from messages "
                                   "where answered", this );
                    t->enqueue( q );
                    q = new Query( "insert into flags (mailbox,uid,flag) "
                                   "select mailbox,uid,"
                                   "(select id from flag_names"
                                   " where name='\\Flagged') from messages "
                                   "where flagged", this );
                    t->enqueue( q );
                    q = new Query( "insert into flags (mailbox,uid,flag) "
                                   "select mailbox,uid,"
                                   "(select id from flag_names"
                                   " where name='\\Draft') from messages "
                                   "where draft", this );
                    t->enqueue( q );
                    q = new Query( "insert into flags (mailbox,uid,flag) "
                                   "select mailbox,uid,"
                                   "(select id from flag_names"
                                   " where name='\\Seen') from messages "
                                   "where seen", this );
                    t->enqueue( q );
                    q = new Query( "alter table messages drop deleted", this );
                    t->enqueue( q );
                    q = new Query( "alter table messages drop answered", this );
                    t->enqueue( q );
                    q = new Query( "alter table messages drop flagged", this );
                    t->enqueue( q );
                    q = new Query( "alter table messages drop draft", this );
                    t->enqueue( q );
                    q = new Query( "alter table messages drop seen", this );
                    t->enqueue( q );
                    t->execute();
                    substate = 1;
                }

                if ( substate == 1 ) {
                    if ( !q->done() )
                        return;
                    l->log( "Done.", Log::Debug );
                    substate = 0;
                }
            }

            if ( revision == 4 ) {
                if ( substate == 0 ) {
                    l->log( "Adding hf_mup, af_mu, fl_mu indices.",
                            Log::Debug );
                    q = new Query( "create index hf_mup on "
                                   "header_fields (mailbox,uid,part)", this );
                    t->enqueue( q );
                    q = new Query( "create index af_mu on "
                                   "address_fields (mailbox,uid)", this );
                    t->enqueue( q );
                    q = new Query( "create index fl_mu on "
                                   "flags (mailbox,uid)", this );
                    t->enqueue( q );
                    t->execute();
                    substate = 1;
                }

                if ( substate == 1 ) {
                    if ( !q->done() )
                        return;
                    l->log( "Done.", Log::Debug );
                    substate = 0;
                }
            }

            if ( revision == 5 ) {
                if ( substate == 0 ) {
                    l->log( "Moving bytes/lines to part_numbers.",
                            Log::Debug );
                    q = new Query( "alter table part_numbers add "
                                   "bytes integer", this );
                    t->enqueue( q );
                    q = new Query( "alter table part_numbers add "
                                   "lines integer", this );
                    t->enqueue( q );
                    q = new Query( "update part_numbers set "
                                   "bytes=bodyparts.bytes,"
                                   "lines=bodyparts.lines from "
                                   "bodyparts where "
                                   "part_numbers.bodypart=bodyparts.id",
                                   this );
                    t->enqueue( q );
                    q = new Query( "alter table bodyparts drop lines",
                                   this );
                    t->enqueue( q );
                    t->execute();
                    substate = 1;
                }

                if ( substate == 1 ) {
                    if ( !q->done() )
                        return;
                    l->log( "Done.", Log::Debug );
                    substate = 0;
                }
            }

            if ( revision == 6 ) {
                if ( substate == 0 ) {
                    l->log( "Adding header_fields.position.", Log::Debug );
                    q = new Query( "alter table header_fields add "
                                   "position integer", this );
                    t->enqueue( q );
                    q = new Query( "alter table header_fields alter part "
                                   "set not null", this );
                    t->enqueue( q );
                    q = new Query( "create temporary sequence hf_pos", this );
                    t->enqueue( q );
                    q = new Query( "declare groups cursor for "
                                   "select distinct mailbox,uid,part "
                                   "from header_fields",
                                   this );
                    t->enqueue( q );
                    q = new Query( "fetch 512 from groups", this );
                    t->enqueue( q );
                    t->execute();
                    substate = 1;
                }

                if ( substate == 1 ) {
                    while ( q->hasResults() ) {
                        Row *r = q->nextRow();

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
                        t->enqueue( u );

                        u = new Query( "alter sequence hf_pos restart with 1",
                                       this );
                        t->enqueue( u );
                    }

                    if ( !q->done() )
                        return;

                    if ( q->rows() != 0 ) {
                        q = new Query( "fetch 512 from groups", this );
                        t->enqueue( q );
                        t->execute();
                        return;
                    }
                    else {
                        t->enqueue( new Query( "close groups", this ) );
                        q = new Query( "alter table header_fields add unique "
                                       "(mailbox,uid,part,position,field)",
                                       this );
                        t->enqueue( q );
                        t->execute();
                        substate = 2;
                    }
                }

                if ( substate == 2 ) {
                    if ( !q->done() )
                        return;
                    l->log( "Done.", Log::Debug );
                    substate = 0;
                }
            }

            if ( revision == 7 ) {
                if ( substate == 0 ) {
                    l->log( "Making address_fields refer to header_fields.",
                            Log::Debug );
                    q = new Query( "delete from address_fields", this );
                    t->enqueue( q );
                    q = new Query( "alter table address_fields drop field",
                                   this );
                    t->enqueue( q );
                    q = new Query( "alter table address_fields add "
                                   "part text", this );
                    t->enqueue( q );
                    q = new Query( "alter table address_fields alter "
                                   "part set not null", this );
                    t->enqueue( q );
                    q = new Query( "alter table address_fields add "
                                   "position integer", this );
                    t->enqueue( q );
                    q = new Query( "alter table address_fields alter "
                                   "position set not null", this );
                    t->enqueue( q );
                    q = new Query( "alter table address_fields add "
                                   "field integer", this );
                    t->enqueue( q );
                    q = new Query( "alter table address_fields alter "
                                   "field set not null", this );
                    t->enqueue( q );
                    q = new Query( "alter table address_fields add foreign key "
                                   "(mailbox,uid,part,position,field) "
                                   "references header_fields "
                                   "(mailbox,uid,part,position,field) "
                                   "on delete cascade", this );
                    t->enqueue( q );
                    t->execute();
                    substate = 1;
                }

                if ( substate == 1 ) {
                    if ( !q->done() )
                        return;
                    l->log( "Done.", Log::Debug );
                    substate = 0;
                }
            }

            if ( revision == 8 ) {
                if ( substate == 0 ) {
                    l->log( "Removing recent_messages.", Log::Debug );
                    q = new Query( "alter table mailboxes add "
                                   "first_recent integer ", this );
                    t->enqueue( q );
                    q = new Query( "update mailboxes set "
                                   "first_recent=coalesce((select min(uid) "
                                   "from recent_messages where "
                                   "mailbox=mailboxes.id),uidnext)", this );
                    t->enqueue( q );
                    q = new Query( "alter table mailboxes alter first_recent "
                                   "set not null", this );
                    t->enqueue( q );
                    q = new Query( "alter table mailboxes alter first_recent "
                                   "set default 1", this );
                    t->enqueue( q );
                    q = new Query( "drop table recent_messages", this );
                    t->enqueue( q );
                    t->execute();
                    substate = 1;
                }

                if ( substate == 1 ) {
                    if ( !q->done() )
                        return;
                    l->log( "Done.", Log::Debug );
                    substate = 0;
                }
            }

            // Remember to update currentRevision when you add something
            // here.

            state = 5;
        }
        if ( state == 5 ) {
            update = new Query( "update mailstore set revision=revision+1",
                                this );
            t->enqueue( update );
            t->execute();
            state = 6;
        }
        if ( state == 6 ) {
            if ( !update->done() )
                return;

            revision = revision+1;
            if ( revision == currentRevision ) {
                t->commit();
                state = 8;
                break;
            }
            state = 2;
        }
    }

    if ( state == 7 || state == 8 ) {
        if ( !t->done() )
            return;

        if ( t->failed() ) {
            l->log( "The schema update transaction failed.", Log::Disaster );
            state = 9;
        }
        else if ( state == 8 ) {
            l->log( "Schema updated to revision " + fn( currentRevision ) );
        }
        Loop::shutdown();
    }

    if ( state == 9 ) {
        // This is a disaster. But do we need to do anything here?
        Loop::shutdown();
    }
}


class AdminHelper: public EventHandler {
public:
    void execute() {
        if ( transaction ) {
            if ( transaction->failed() ) {
                fprintf( stderr, "%s: SQL error: %s\n",
                         name, transaction->error().cstr() );
                status = -1;
            }
            if ( transaction->done() )
                Loop::shutdown();
        }
        else {
            if ( query->failed() ) {
                fprintf( stderr, "%s: SQL error: %s\n",
                         name, query->error().cstr() );
                status = -1;
            }
            if ( query->done() )
                Loop::shutdown();
        }
    }
};


class UserLister: public AdminHelper {
public:
    void execute() {
        AdminHelper::execute();
        if ( !query->done() )
            return;
        Row * r = query->nextRow();
        while ( r ) {
            fprintf( stdout, "%-8s %s@%s\n",
                     r->getString( "login" ).cstr(),
                     r->getString( "localpart" ).cstr(),
                     r->getString( "domain" ).cstr() );
            r = query->nextRow();
        }
    }
};


static void error( String m )
{
    fprintf( stderr, "%s: %s\nUsage:\n  %s verb noun arguments\n",
             name, m.cstr(), name );
    fprintf( stdout,
             "Examples:\n"
             "    %s create user <login> <password> <address@domain>\n"
             "    %s rename user <login> <newlogin>\n"
             "    %s rename user <login> <newaddress@newdomain>\n"
             "    %s delete user <login>\n",
             name, name, name, name );
    exit( -1 );
}


static void addEternal( void * v, const char * t )
{
    Allocator::addEternal( v, t );
}


static void createUser( String login, String password, String address )
{
    uint i = 0;
    while ( i < login.length() &&
            ( ( login[i] >= '0' && login[i] <= '9' ) ||
              ( login[i] >= 'a' && login[i] <= 'z' ) ||
              ( login[i] >= 'Z' && login[i] <= 'Z' ) ) )
        i++;
    if ( i < login.length() ||
         login == "anonymous" ||
         login == "anyone" ||
         login == "group" ||
         login == "user" )
    {
        fprintf( stderr, "%s: Invalid username: '%s'.\n",
                 name, login.cstr() );
        Loop::shutdown();
        return;
    }

    User * u = new User;
    addEternal( u, "user" );
    u->setLogin( login );
    u->setSecret( password );
    if ( !u->valid() )
        error( u->error() );

    if ( !address.isEmpty() ) {
        AddressParser p( address );
        if ( !p.error().isEmpty() )
            error( p.error() );
        if ( p.addresses()->count() != 1 )
            error( "At most one address may be present" );
        u->setAddress( p.addresses()->first() );
    }

    query = u->create( new AdminHelper );
    if ( !query || query->failed() ) {
        fprintf( stderr, "%s: Internal error. Couldn't create user.\n",
                 name );
        Loop::shutdown();
    }
}


static void deleteUser( const char * login )
{
    User * u = new User;
    addEternal( u, "user" );
    u->setLogin( login );
    u->remove( new AdminHelper );
}


void changePassword( const char * login, const char * password )
{
    User * u = new User;
    addEternal( u, "user" );
    u->setLogin( login );
    u->setSecret( password );
    query = u->changeSecret( new AdminHelper );
    if ( !query || query->failed() ) {
        fprintf( stderr, "%s: Internal error. "
                 "Couldn't change password for user %s.\n", name, login );
        Loop::shutdown();
    }
}


void listUsers( const char * pattern )
{
    String p;
    uint i = 0;
    while ( pattern[i] ) {
        if ( pattern[i] == '*' )
            p.append( '%' );
        else
            p.append( pattern[i] );
        i++;
    }
    query = new Query( "select login from users where login like $1",
                       new UserLister );
    query = new Query( "select "
                       "users.login, addresses.localpart, addresses.domain "
                       "from users, addresses "
                       "where users.login like $1 "
                       "and users.address=addresses.id",
                       new UserLister );
    query->bind( 1, p );
    query->execute();
}


int main( int argc, char *argv[] )
{
    Scope global;

    // initial setup
    String verb, noun;
    status = 0;

    name = argv[0];
    verb = argv[1];
    noun = argv[2];
    verb = verb.lower();
    noun = noun.lower();

    // undocumented synomyms to please irritable users like... me. uh.
    if ( verb == "add" || verb == "new" )
        verb = "create";
    else if ( verb == "remove" || verb == "del" )
        verb = "delete";

    // get rid of illegal verbs and nouns
    if ( verb != "create" &&
         verb != "rename" &&
         verb != "change" &&
         verb != "list" &&
         verb != "delete" &&
         verb != "migrate" )
        error( verb + ": unknown verb" );

    if ( noun != "user" &&
         noun != "users" &&
         noun != "mailbox" &&
         noun != "password" &&
         verb != "migrate" )
        error( noun + ": unknown noun" );

    // typical mailstore crud
    Configuration::setup( "mailstore.conf" );

    Loop::setup();

    Log l( Log::General );
    global.setLog( &l );
    LogClient::setup( "ms" );

    OCClient::setup();
    Database::setup();
    AddressCache::setup();
    Configuration::report();
    Mailbox::setup();

    // check each combination
    if ( verb == "create" && noun == "user" ) {
        if ( argc <= 4 )
            error( "Too few arguments (need login and password)" );
        else if ( argc == 5 )
            createUser( argv[3], argv[4], "" );
        else if ( argc == 6 )
            createUser( argv[3], argv[4], argv[5] );
        else
            error( "Unknown argument following login, password and address" );
    }
    else if ( verb == "delete" && noun == "user" ) {
        if ( argc <= 2 )
            error( "Too few arguments (need login)" );
        else
            deleteUser( argv[3] );
    }
    else if ( verb == "change" && noun == "password" ) {
        if ( argc == 5 )
            changePassword( argv[3], argv[4] );
        else
            error( "Wrong arguments (need login/address and password)" );
    }
    else if ( verb == "list" && noun == "users" ) {
        if ( argc > 4 )
            error( "Too many arguments (need login glob pattern)" );
        else if ( argc == 4 )
            listUsers( argv[3] );
        else
            listUsers( "*" );
    }
    else if ( ( verb == "create" || verb == "delete" ) &&
              noun == "mailbox" )
    {
        if ( argc < 4 )
            error( "Too few arguments (need a mailbox name)." );
        else if ( argc > 4 )
            error( "Unknown argument following mailbox name." );

        if ( verb == "create" ) {
            Mailbox * m = new Mailbox( argv[3] );
            addEternal( m, "mailbox" );
            transaction = m->create( new AdminHelper, 0 );
            if ( !transaction ) {
                fprintf( stderr,
                         "%s: Internal error: Could not create transaction\n",
                         argv[3] );
                exit( -1 );
            }
        }
        else if ( verb == "delete" ) {
            // Mailbox tree isn't set up yet. we hack and set up a
            // query on our own. this is broken - there's no error
            // message if the mailbo did not exist.
            query = new Query( "update mailboxes set deleted='t' "
                               "where name=$1 and deleted='f'",
                               new AdminHelper );
            query->bind( 1, argv[3] );
            query->execute();
        }
    }
    else if ( verb == "migrate" ) {
        UpdateSchema *s = new UpdateSchema;
        s->execute();
    }
    else { // .. and if we don't know that verb/noun combination:
        error( "Sorry, not implemented: " + verb + " " + noun );
    }

    if ( query )
        addEternal( query, "query to be run" );
    if ( transaction )
        addEternal( transaction, "query to be run" );
    Loop::start();
    return status;
}
