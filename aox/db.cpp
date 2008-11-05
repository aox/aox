// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "db.h"

#include "query.h"
#include "schema.h"
#include "granter.h"
#include "postgres.h"
#include "recipient.h"
#include "transaction.h"
#include "configuration.h"

#include <stdio.h>


static const char * versions[] = {
    "", "", "0.91", "0.92", "0.92", "0.92 to 0.93", // 0-5
    "0.93", "0.93", "0.94 to 0.95", "0.96 to 0.97", // 6-9
    "0.97", "0.97", "0.98", "0.99", "1.0", "1.01",  // 10-15
    "1.05", "1.05", "1.06", "1.07", "1.08", "1.09", // 16-21
    "1.10", "1.10", "1.11", "1.11", "1.11", "1.11", // 22-27
    "1.12", "1.12", "1.12", "1.12", "1.13", "1.13", // 28-33
    "1.15", "1.15", "1.16", "1.16", "1.16", "1.17", // 34-39
    "1.17", "1.17", "1.17", "2.0", "2.0", "2.0",    // 40-45
    "2.0", "2.0", "2.0", "2.01", "2.01", "2.01",    // 46-51
    "2.01", "2.01", "2.01", "2.02", "2.04", "2.04", // 52-57
    "2.05", "2.05", "2.06", "2.06", "2.06", "2.06", // 58-63
    "2.06", "2.06", "2.06", "2.10", "2.10", "2.10", // 64-69
    "2.10", "2.10", "2.10", "2.11", "2.11", "2.11", // 70-75
    "2.12", "2.13", "2.13"
};
static int nv = sizeof( versions ) / sizeof( versions[0] );


/*! \class ShowSchema schema.h
    This class handles the "aox show schema" command.
*/

ShowSchema::ShowSchema( StringList * args )
    : AoxCommand( args ), q( 0 )
{
}


void ShowSchema::execute()
{
    if ( !q ) {
        end();

        database();
        q = new Query( "select revision from mailstore", this );
        q->execute();
    }

    if ( !q->done() )
        return;

    Row * r = q->nextRow();
    if ( r ) {
        int rev = r->getInt( "revision" );

        String s;
        if ( rev >= nv ) {
            s = "too new for ";
            s.append( Configuration::compiledIn( Configuration::Version ) );
        }
        else {
            s = versions[rev];
            if ( rev == nv-1 )
                s.append( " - latest known version" );
            else
                s.append( " - needs to be upgraded" );
        }

        if ( !s.isEmpty() )
            s = " (" + s + ")";
        printf( "%d%s\n", rev, s.cstr() );
    }

    finish();
}



/*! \class UpgradeSchema schema.h
    This class handles the "aox upgrade schema" command.
*/

UpgradeSchema::UpgradeSchema( StringList * args )
    : AoxCommand( args ), q( 0 )
{
}


void UpgradeSchema::execute()
{
    if ( !q ) {
        parseOptions();
        end();

        bool commit = true;
        if ( opt( 'n' ) > 0 )
            commit = false;

        database( true );
        Schema * s = new Schema( this, true, commit );
        q = s->result();
        s->execute();
    }

    if ( !q->done() )
        return;

    finish();
}



/*! \class Vacuum Vacuum.h
    This class handles the "aox vacuum" command.
*/

Vacuum::Vacuum( StringList * args )
    : AoxCommand( args ), t( 0 )
{
}


void Vacuum::execute()
{
    if ( !t ) {
        parseOptions();
        end();

        database( true );
        t = new Transaction( this );
        uint days = Configuration::scalar( Configuration::UndeleteTime );

        Query * q;

        q = new Query( "delete from deliveries "
                       "where injected_at<current_timestamp-'" +
                       fn( days ) + " days'::interval "
                       "and id in "
                       "(select delivery from delivery_recipients "
                       " where action!=$1 and action!=$2) "
                       "and id not in "
                       "(select delivery from delivery_recipients "
                       " where action=$1 or action=$2)", 0 );
        q->bind( 1, Recipient::Unknown );
        q->bind( 2, Recipient::Delayed );
        t->enqueue( q );

        q = new Query(
            "delete from messages where id in "
            "(select dm.message from deleted_messages dm"
            " left join mailbox_messages mm on (dm.message=mm.message)"
            " left join deliveries d on (dm.message=d.message)"
            " where mm.message is null and d.message is null"
            " and dm.deleted_at<current_timestamp-'" + fn( days ) +
            " days'::interval)", 0
        );
        t->enqueue( q );

        q = new Query( "delete from bodyparts where id in (select id "
                       "from bodyparts b left join part_numbers p on "
                       "(b.id=p.bodypart) where bodypart is null)", 0 );
        t->enqueue( q );
        t->commit();
    }

    if ( !t->done() )
        return;

    if ( t->failed() )
        error( "Vacuuming failed" );

    finish();
}


/*! \class GrantPrivileges db.h
    This class handles the "aox grant privileges" command.
*/


GrantPrivileges::GrantPrivileges( StringList * args )
    : AoxCommand( args ), commit( true ), t( 0 ), g( 0 )
{
}


void GrantPrivileges::execute()
{
    if ( !t ) {
        parseOptions();
        String name = next();
        end();

        if ( name.isEmpty() )
            name = Configuration::text( Configuration::DbUser );

        if ( opt( 'n' ) > 0 )
            commit = false;

        database( true );

        t = new Transaction( this );
        g = new Granter( name, t );
        g->execute();
    }

    if ( !g || !g->done() )
        return;

    if ( commit )
        t->commit();
    else
        t->rollback();

    if ( !t->done() )
        return;

    if ( t->failed() )
        error( "Couldn't grant privileges: " + t->error() );

    finish();
}


struct TunableIndex {
    const char * name;
    const char * table;
    const char * definition;
    bool writing;
    bool reading;
    bool advanced;
} tunableIndices[] = {
    { "pn_b", "part_numbers",
      "CREATE INDEX pn_b ON part_numbers "
      "USING btree (bodypart)",
      false, true, true },
    { "ald", "addresses",
      "CREATE INDEX ald ON addresses "
      "USING btree (lower(localpart), lower(domain))",
      false, true, true },
    { "af_mp", "address_fields",
      "CREATE INDEX af_mp ON address_fields "
      "USING btree (message, part)",
      false, true, true },
    { "fl_mu", "flags",
      "CREATE INDEX fl_mu ON flags "
      "USING btree (mailbox, uid)",
      false, true, true },
    { "dm_mud", "deleted_messages",
      "CREATE INDEX dm_mud ON deleted_messages "
      "USING btree (mailbox, uid, deleted_at)",
      false, true, true },
    { "mm_m", "mailbox_messages",
      "CREATE INDEX mm_m ON mailbox_messages "
      "USING btree (message)",
      false, true, true },
    { "dm_m", "deleted_messages",
      "CREATE INDEX dm_m ON deleted_messages "
      "USING btree (message)",
      false, true, true },
    { "df_m", "date_fields",
      "CREATE INDEX df_m ON date_fields "
      "USING btree (message)",
      false, true, true },
    { "hf_msgid", "header_fields",
      "CREATE INDEX hf_msgid ON header_fields "
      "USING btree (value) WHERE (field = 13)",
      false, true, true },
    { "dm_mm", "deleted_messages",
      "CREATE INDEX dm_mm ON deleted_messages "
      "USING btree (mailbox, modseq)",
      false, true, true },
    { "b_text", "bodyparts",
      "CREATE INDEX b_text ON bodyparts "
      "USING gin (to_tsvector('simple'::regconfig, text)) "
      "WHERE (length(text) < (1024 * 1024))",
      false, false, true },
    { 0, 0, 0, false, false, false }
};


class TuneDatabaseData
    : public Garbage
{
public:
    TuneDatabaseData(): mode( Reading ), t( 0 ), find( 0 ), set( false ) {}
    enum Mode {
        Writing, Reading, Advanced
    };
    Mode mode;
    Transaction * t;
    Query * find;
    bool set;
};


/*! \class TuneDatabase db.h
    This class handles the "aox tune database" command.
*/


TuneDatabase::TuneDatabase( StringList * args )
    : AoxCommand( args ), d( new TuneDatabaseData )
{
}


void TuneDatabase::execute()
{
    if ( !d->t ) {
        parseOptions();
        String mode = next().lower();
        if ( mode == "mostly-writing" )
            d->mode = TuneDatabaseData::Writing;
        else if ( mode == "mostly-reading" )
            d->mode = TuneDatabaseData::Reading;
        else if ( mode == "advanced-reading" )
            d->mode = TuneDatabaseData::Advanced;
        else
            error( "Unknown database mode.\n"
                   "Supported: mostly-writing, mostly-reading and "
                   "advanced-reading" );
        database( true );

        d->t = new Transaction( this );

        StringList indexnames;
        uint i = 0;
        while ( tunableIndices[i].name ) {
            indexnames.append( tunableIndices[i].name );
            ++i;
        }
        d->find = new Query( "select indexname::text from pg_indexes where "
                             "schemaname=$1 and indexname=any($2::text[])",
                             this );
        d->find->bind( 1, Configuration::text( Configuration::DbSchema ) );
        d->find->bind( 2, indexnames );

        d->t->enqueue( d->find );
        d->t->execute();
    }

    if ( !d->find->done() )
        return;

    if ( d->t->failed() )
        error( "Cannot tune database" );

    if ( !d->set ) {
        StringList present;
        while ( d->find->hasResults() ) {
            Row * r = d->find->nextRow();
            String name = r->getString( "indexname" );
            uint i = 0;
            while ( tunableIndices[i].name &&
                    name != tunableIndices[i].name )
                i++;
            if ( tunableIndices[i].name )
                present.append( tunableIndices[i].name );
        }
        uint i = 0;
        while ( tunableIndices[i].name ) {
            bool wanted = false;
            switch ( d->mode ) {
            case TuneDatabaseData::Writing:
                wanted = tunableIndices[i].writing;
                break;
            case TuneDatabaseData::Reading:
                wanted = tunableIndices[i].reading;
                break;
            case TuneDatabaseData::Advanced:
                wanted = tunableIndices[i].advanced;
                break;
            }
            Query * q = 0;
            if ( wanted && !present.find( tunableIndices[i].name ) ) {
                if ( String( tunableIndices[i].name ) == "b_text" &&
                     Postgres::version() < 80300 ) {
                    printf( "Error: "
                            "Full-text indexing needs PostgreSQL 8.3\n" );
                }
                else {
                    q = new Query( tunableIndices[i].definition, 0 );
                    printf( "Executing %s;\n", tunableIndices[i].definition );
                }
            }
            else if ( present.find( tunableIndices[i].name ) && !wanted ) {
                q = new Query( String("drop index ") + tunableIndices[i].name,
                               0 );
                printf( "Dropping index %s.\n",
                        tunableIndices[i].name );
            }
            if ( q )
                d->t->enqueue( q );
            i++;
        }
        d->t->enqueue( new Query( "notify database_retuned", 0 ) );
        d->t->commit();
        d->set = true;
    }

    if ( !d->t->done() )
        return;

    finish();
}
