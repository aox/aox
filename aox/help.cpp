// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "help.h"

#include "estringlist.h"

#include <stdio.h>


/*! \class Help help.h
    This class handles the "aox help" command.
*/

Help::Help( EStringList * args )
    : AoxCommand( args )
{
    execute();
}


static AoxFactory<Help>
f( "help", "", "Offer help on a commands and more",
   "XXX writeme" );


void Help::execute()
{
    EString a = next().lower();

    if ( a == "add" || a == "new" )
        a = "create";
    else if ( a == "del" || a == "remove" )
        a = "delete";

    EString b;
    if ( AoxCommandMap::needsNoun( a ) )
        b = next().lower();

    EString about = AoxCommandMap::aboutCommand( a, b );
    if ( !about.isEmpty() ) {
        printf( "aox %s %s -- %s\n%s",
                a.cstr(), b.cstr(), AoxCommandMap::inBrief( a, b ).cstr(),
                about.cstr() );
    }
    else if ( AoxCommandMap::validVerbs()->contains( a ) ) {
        printf( "aox %s: Valid arguments:\n", a.cstr() );
        EStringList::Iterator i( AoxCommandMap::validNouns( a ) );
        while ( i ) {
            printf( "  %s -- %s\n",
                    i->cstr(), AoxCommandMap::inBrief( a, *i ).cstr() );
            ++i;
        }
    }
    else if ( a == "commands" || a.isEmpty() ) {
        printf(
            "aox: Command summary:\n"
            "  Server management:\n"
            "    start\n"
            "    stop\n"
            "    restart\n"
            "    show status\n"
            "\n"
            "  Configuration:\n"
            "    check config\n"
            "    show build\n"
            "    show configuration\n"
            "    tune database\n"
            "\n"
            "  Administration:\n"
            "    list <users|mailboxes|aliases|rights>\n"
            "    add <user|mailbox|alias>\n"
            "    delete <user|mailbox|alias>\n"
            "    change <username|password|address>\n"
            "    setacl\n"
            "\n"
            "  Other:\n"
            "    show queue\n"
            "    undelete\n"
            "    vacuum\n"
            "    ...\n"
            "\n"
            "  Use \"aox help <command name>\" for more specific help,\n"
            "  \"aox help allcommands\" for a complete list of commands or\n"
            "  e.g. \"aox help show\" for a list of arguments to show.\n"
            );
    }
    else if ( a == "allcommands" ) {
        printf( "aox: Valid commands:\n" );
        EStringList::Iterator v( AoxCommandMap::validVerbs() );
        while ( v ) {
            EStringList::Iterator n( AoxCommandMap::validNouns( *v ) );
            while ( n ) {
                printf( "  %s %s -- %s\n",
                        v->cstr(), n->cstr(),
                        AoxCommandMap::inBrief( *v, *n ).cstr() );
                ++n;
            }
            ++v;
        }
    }
    else {
        printf( "aox %s: Invalid command.\n  Valid commands:\n%s\n",
                a.cstr(),
                AoxCommandMap::validVerbs()->join( ", " )
                .wrapped( 70, "    ", "    ", false ).cstr() );
    }

    finish();
}
