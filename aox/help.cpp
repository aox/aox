// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "help.h"

#include "configuration.h"

#include <stdio.h>


/*! \class Help help.h
    This class handles the "aox help" command.
*/

Help::Help( EStringList * args )
    : AoxCommand( args )
{
}


static AoxFactory<Help>
f( "help", "", "Offer help on a commands and more",
   "XXX writeme" );


void Help::execute()
{
    EString a = next().lower();
    EString b = next().lower();

    if ( a == "create" || a == "new" )
        a = "add";
    else if ( a == "del" || a == "remove" )
        a = "delete";

    // We really need a better way of constructing help texts.
    // (And better help text, now that I think about it.)

        fprintf(
            stderr,
            "  Available aox commands:\n\n"
            "    start              -- Server management.\n"
            "    stop\n"
            "    restart\n\n"
            "    check config       -- Check that the configuration is sane.\n"
            "    show status        -- Are the servers running?\n"
            "    show build         -- Displays compile-time configuration.\n"
            "    show counts        -- Shows number of users, messages etc.\n"
            "    show configuration -- Displays runtime configuration.\n"
            "    show queue         -- Displays mail queued for delivery.\n"
            "\n"
            "    show schema        -- Displays the existing schema revision.\n"
            "    upgrade schema     -- Upgrades an older schema to work with\n"
            "                          the current server.\n"
            "    update database    -- Updates the database contents, if the\n"
            "                          current server needs to.\n"
            "    tune database      -- Adjust database to suit expected use.\n"
            "\n"
            "                       -- User and mailbox management.\n"
            "    list <users|mailboxes|aliases|rights>\n"
            "    add <user|mailbox|alias>\n"
            "    delete <user|mailbox|alias>\n"
            "    change <username|password|address>\n"
            "    setacl\n"
            "\n"
            "    reparse            -- Try to reparse messages that could not\n"
            "                          be parsed by an older server.\n"
            "\n"
            "    undelete           -- Undelete accidentally removed messages.\n"
            "    vacuum             -- Permanently remove deleted messages.\n"
            "    anonymise          -- Anonymise a message for a bug report.\n"
            "\n"
            "  Use \"aox help command name\" for more specific help.\n"
        );
        fprintf(
            stderr,
            "  aox -- A command-line interface to Archiveopteryx.\n\n"
            "    Synopsis: aox <verb> <noun> [options] [arguments]\n\n"
            "    Use \"aox help commands\" for a list of commands.\n"
            "    Use \"aox help start\" for help with \"start\".\n"
        );

    finish();
}
