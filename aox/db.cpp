// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "db.h"

#include "query.h"
#include "schema.h"
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
    "2.10", "2.10", "2.10", "2.11", "2.11", "2.11"  // 70-75
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
        error( t->error() );

    finish();
}


/*! \class GrantPrivileges db.h
    This class handles the "aox grant privileges" command.
*/


GrantPrivileges::GrantPrivileges( StringList * args )
    : AoxCommand( args ), q( 0 )
{
}


void GrantPrivileges::execute()
{
    if ( !q ) {
        parseOptions();
        String name = next();
        end();

        if ( name.isEmpty() )
            error( "No database username specified." );

        database( true );

        q = new Query(
            "revoke all on access_keys, address_fields, addresses, "
            "addresses_id_seq, aliases, aliases_id_seq, annotation_names, "
            "annotation_names_id_seq, annotations, annotations_id_seq, "
            "autoresponses, autoresponses_id_seq, bodypart_ids, bodyparts, "
            "date_fields, deleted_messages, deliveries, deliveries_id_seq, "
            "delivery_recipients, delivery_recipients_id_seq, field_names, "
            "field_names_id_seq, flag_names, flag_names_id_seq, flags, "
            "group_members, groups, groups_id_seq, header_fields, "
            "header_fields_id_seq, mailbox_messages, mailboxes, "
            "mailboxes_id_seq, mailstore, messages, messages_id_seq, "
            "namespaces, namespaces_id_seq, part_numbers, permissions, "
            "scripts, scripts_id_seq, subscriptions, subscriptions_id_seq, "
            "thread_members, threads, threads_id_seq, unparsed_messages, "
            "users, users_id_seq, views, views_id_seq, connections, "
            "connections_id_seq, fileinto_targets, fileinto_targets_id_seq "
            "from " + name.quoted(),
            this
        );
        q->execute();

        q = new Query(
            "grant select on mailstore, addresses, namespaces, users, "
            "groups, group_members, mailboxes, aliases, permissions, "
            "messages, bodyparts, part_numbers, field_names, "
            "header_fields, address_fields, date_fields, threads, "
            "thread_members, flag_names, flags, subscriptions, scripts, "
            "annotation_names, annotations, views, deleted_messages, "
            "deliveries, delivery_recipients, access_keys, autoresponses, "
            "mailbox_messages, fileinto_targets to " + name.quoted(),
            this
        );
        q->execute();

        q = new Query(
            "grant insert on addresses, mailboxes, permissions, messages, "
            "bodyparts, part_numbers, field_names, header_fields, "
            "address_fields, date_fields, threads, thread_members, "
            "flag_names, flags, subscriptions, scripts, annotation_names, "
            "annotations, views, deleted_messages, deliveries, "
            "delivery_recipients, access_keys, unparsed_messages, "
            "autoresponses, mailbox_messages, connections, "
            "fileinto_targets to " + name.quoted(),
            this
        );
        q->execute();

        q = new Query(
            "grant delete on permissions, flags, subscriptions, annotations, "
            "views, scripts, deliveries, access_keys, fileinto_targets "
            "to " + name.quoted(),
            this
        );
        q->execute();

        q = new Query(
            "grant update on mailstore, permissions, mailboxes, aliases, "
            "annotations, views, scripts, deliveries, delivery_recipients, "
            "mailbox_messages, threads to " + name.quoted(),
            this
        );
        q->execute();

        q = new Query(
            "grant select, update on messages_id_seq, addresses_id_seq, "
            "aliases_id_seq, annotation_names_id_seq, bodypart_ids, "
            "field_names_id_seq, flag_names_id_seq, groups_id_seq, "
            "header_fields_id_seq, mailboxes_id_seq, namespaces_id_seq, "
            "scripts_id_seq, subscriptions_id_seq, threads_id_seq, "
            "users_id_seq, views_id_seq, deliveries_id_seq, "
            "delivery_recipients_id_seq, annotations_id_seq, "
            "autoresponses_id_seq, connections_id_seq, "
            "fileinto_targets_id_seq to " + name.quoted(),
            this
        );
        q->execute();
    }

    if ( !q->done() )
        return;

    if ( q->failed() )
        error( q->error() );

    finish();
}
