// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "help.h"

#include "configuration.h"

#include <stdio.h>


/*! \class Help help.h
    This class handles the "aox help" command.
*/

Help::Help( StringList * args )
    : AoxCommand( args )
{
}


void Help::execute()
{
    String a = next().lower();
    String b = next().lower();

    if ( a == "create" || a == "new" )
        a = "add";
    else if ( a == "del" || a == "remove" )
        a = "delete";

    // We really need a better way of constructing help texts.
    // (And better help text, now that I think about it.)

    if ( a == "start" ) {
        fprintf(
            stderr,
            "  start -- Start the servers.\n\n"
            "    Synopsis: aox start [-v]\n\n"
            "    Starts the Oryx servers in the correct order.\n"
            "    The -v flag enables (slightly) verbose diagnostic output.\n"
        );
    }
    else if ( a == "stop" ) {
        fprintf(
            stderr,
            "  stop -- Stop the running servers.\n\n"
            "    Synopsis: aox stop [-v]\n\n"
            "    Stops the running Oryx servers in the correct order.\n"
            "    The -v flag enables (slightly) verbose diagnostic output.\n"
        );
    }
    else if ( a == "restart" ) {
        fprintf(
            stderr,
            "  restart -- Restart the servers.\n\n"
            "    Synopsis: aox restart [-v]\n\n"
            "    Restarts the Oryx servers in the correct order.\n"
            "    (Currently equivalent to start && stop.)\n\n"
            "    The -v flag enables (slightly) verbose diagnostic output.\n"
        );
    }
    else if ( a == "show" && b == "status" ) {
        fprintf(
            stderr,
            "  show status -- Display a summary of the running servers.\n\n"
            "    Synopsis: aox show status [-v]\n\n"
            "    Displays a summary of the running Oryx servers.\n"
            "    The -v flag enables (slightly) verbose diagnostic output.\n"
        );
    }
    else if ( a == "show" && ( b == "cf" || b.startsWith( "conf" ) ) ) {
        fprintf(
            stderr,
            "  show configuration -- Display configuration variables.\n\n"
            "    Synopsis: aox show conf [ -p -v ] [variable-name]\n\n"
            "    Displays variables configured in archiveopteryx.conf.\n\n"
            "    If a variable-name is specified, only that variable\n"
            "    is displayed.\n\n"
            "    The -v flag displays only the value of the variable.\n"
            "    The -p flag restricts the results to variables whose\n"
            "    value has been changed from the default.\n\n"
            "    configuration may be abbreviated as cf.\n\n"
            "    Examples:\n\n"
            "      aox show configuration\n"
            "      aox show cf -p\n"
            "      aox show cf -v imap-address\n"
        );
    }
    else if ( a == "show" && b.startsWith( "build" ) ) {
        fprintf(
            stderr,
            "  show build -- Display build settings.\n\n"
            "    Synopsis: aox show build\n\n"
            "    Displays the build settings used for this installation.\n"
            "    (As configured in Jamsettings.)\n"
        );
    }
    else if ( a == "show" && b.startsWith( "count" ) ) {
        fprintf(
            stderr,
            "  show counts -- Show number of users, messages etc..\n\n"
            "    Synopsis: aox show counts [-f]\n\n"
            "    Displays the number of rows in the most important tables,\n"
            "    as well as the total size of the mail stored.\n"
            "\n"
            "    The -f flag makes aox collect slow-but-accurate counts.\n"
            "    Without it, by default, you get quick estimates.\n"
        );
    }
    else if ( a == "show" && b == "schema" ) {
        fprintf(
            stderr,
            "  show schema -- Display schema revision.\n\n"
            "    Synopsis: aox show schema\n\n"
            "    Displays the revision of the existing database schema.\n"
        );
    }
    else if ( a == "upgrade" && b == "schema" ) {
        fprintf(
            stderr,
            "  upgrade schema -- Upgrade the database schema.\n\n"
            "    Synopsis: aox upgrade schema [-n]\n\n"
            "    Checks that the database schema is one that this version of\n"
            "    Archiveopteryx is compatible with, and updates it if needed.\n"
            "\n"
            "    The -n flag causes aox to perform the SQL statements for the\n"
            "    schema upgrade and report on their status without COMMITting\n"
            "    the transaction (i.e. see what the upgrade would do, without\n"
            "    changing anything).\n"
        );
    }
    else if ( a == "update" && b == "database" ) {
        fprintf(
            stderr,
            "  update database -- Update the database contents.\n\n"
            "    Synopsis: aox update database\n\n"
            "    Performs any updates to the database contents which are too\n"
            "    slow for inclusion in \"aox upgrade schema\". This command is\n"
            "    meant to be used while the server is running. It does its\n"
            "    work in small chunks, so it can be restarted at any time,\n"
            "    and is tolerant of interruptions.\n"
        );
    }
    else if ( a == "list" && b == "mailboxes" ) {
        fprintf(
            stderr,
            "  list mailboxes -- Display existing mailboxes.\n\n"
            "    Synopsis: aox list mailboxes [-d] [-o user] [pattern]\n\n"
            "    Displays a list of mailboxes matching the specified shell\n"
            "    glob pattern. Without a pattern, all mailboxes are listed.\n\n"
            "    The -d flag includes deleted mailboxes in the list.\n\n"
            "    The \"-o username\" flag restricts the list to mailboxes\n"
            "    owned by the specified user.\n\n"
            "    The -s flag shows a count of messages and the total size\n"
            "    of messages in each mailbox.\n\n"
            "    ls is an acceptable abbreviation for list.\n\n"
            "    Examples:\n\n"
            "      aox list mailboxes\n"
            "      aox ls mailboxes /users/ab?cd*\n"
        );
    }
    else if ( a == "list" && b == "users" ) {
        fprintf(
            stderr,
            "  list users -- Display existing users.\n\n"
            "    Synopsis: aox list users [pattern]\n\n"
            "    Displays a list of users matching the specified shell\n"
            "    glob pattern. Without a pattern, all users are listed.\n\n"
            "    ls is an acceptable abbreviation for list.\n\n"
            "    Examples:\n\n"
            "      aox list users\n"
            "      aox ls users ab?cd*\n"
        );
    }
    else if ( a == "list" && b == "aliases" ) {
        fprintf(
            stderr,
            "  list aliases -- Display delivery aliases.\n\n"
            "    Synopsis: aox list aliases [pattern]\n\n"
            "    Displays a list of aliases where either the address or the\n"
            "    target mailbox matches the specified shell glob pattern.\n"
            "    Without a pattern, all aliases are listed.\n\n"
            "    ls is an acceptable abbreviation for list.\n\n"
            "    Examples:\n\n"
            "      aox list aliases\n"
            "      aox ls aliases /users/\\*\n"
        );
    }
    else if ( a == "list" && b == "rights" ) {
        fprintf(
            stderr,
            "  list rights -- Display permissions on a mailbox.\n\n"
            "    Synopsis: aox list rights <mailbox> [username]\n\n"
            "    Displays a list of users and the rights they have been\n"
            "    granted to the specified mailbox. If a username is given,\n"
            "    only that user's rights are displayed.\n\n"
            "    ls is an acceptable abbreviation for list.\n\n"
            "    Examples:\n\n"
            "      aox list rights /archives/mailstore-users anonymous\n"
            "      aox light right /users/xyzzy/shared\n"
        );
    }
    else if ( a == "add" && b == "user" ) {
        fprintf(
            stderr,
            "  add user -- Create a new user.\n\n"
            "    Synopsis:\n"
            "      aox add user <username> <password> <email-address>\n"
            "      aox add user -p <username> <email-address>\n\n"
            "    Creates a new Archiveopteryx user with the given username,\n"
            "    password, and email address.\n\n"
            "    The -p flag causes the password to be read interactively, and\n"
            "    not from the command line.\n\n"
            "    Examples:\n\n"
            "      aox add user nirmala secret nirmala@example.org\n"
        );
    }
    else if ( a == "delete" && b == "user" ) {
        fprintf(
            stderr,
            "  delete user -- Delete a user.\n\n"
            "    Synopsis: aox delete user [-f] <username>\n\n"
            "    Deletes the Archiveopteryx user with the specified name.\n\n"
            "    The -f flag causes any mailboxes owned by the user to be "
            "deleted too.\n"
        );
    }
    else if ( a == "change" && b == "password" ) {
        fprintf(
            stderr,
            "  change password -- Change a user's password.\n\n"
            "    Synopsis:\n"
            "      aox change password <username> <new-password>\n"
            "      aox change password -p <username>\n\n"
            "    Changes the specified user's password.\n\n"
            "    The -p flag causes the password to be read interactively, and\n"
            "    not from the command line.\n\n"
        );
    }
    else if ( a == "change" && b == "username" ) {
        fprintf(
            stderr,
            "  change username -- Change a user's name.\n\n"
            "    Synopsis: aox change username <username> <new-username>\n\n"
            "    Changes the specified user's username.\n"
        );
    }
    else if ( a == "change" && b == "address" ) {
        fprintf(
            stderr,
            "  change address -- Change a user's email address.\n\n"
            "    Synopsis: aox change address <username> <new-address>\n\n"
            "    Changes the specified user's email address.\n"
        );
    }
    else if ( a == "add" && b == "mailbox" ) {
        fprintf(
            stderr,
            "  add mailbox -- Create a new mailbox.\n\n"
            "    Synopsis: aox add mailbox <name> [username]\n\n"
            "    Creates a new mailbox with the specified name and,\n"
            "    if a username is specified, owned by that user.\n\n"
            "    The mailbox name must be fully-qualified (begin with /),\n"
            "    unless a username is specified, in which case unqualified\n"
            "    names are assumed to be under the user's home directory.\n"
        );
    }
    else if ( a == "delete" &&
              ( b == "mailbox" || b == "view" ) )
    {
        fprintf(
            stderr,
            "  delete mailbox -- Delete a mailbox.\n\n"
            "    Synopsis: aox delete mailbox <name>\n\n"
            "    Deletes the specified mailbox.\n\n"
            "    This command is synonymous with \"aox delete view\", and may\n"
            "    be used to delete mailboxes created with \"aox add view\".\n"
        );
    }
    else if ( a == "add" && b == "alias" ) {
        fprintf(
            stderr,
            "  add alias -- Create a delivery alias.\n\n"
            "    Synopsis: aox add alias <address> <destination>\n\n"
            "    Creates an alias that instructs the L/SMTP server to accept\n"
            "    mail to a given address, and deliver it to a given mailbox.\n"
            "    The destination mailbox can be specified by name (starting\n"
            "    with '/') or by email address (ie. creating another alias for\n"
            "    the same mailbox).\n"
        );
    }
    else if ( a == "delete" && b == "alias" ) {
        fprintf(
            stderr,
            "  delete alias -- Delete a delivery alias.\n\n"
            "    Synopsis: aox delete alias <address>\n\n"
            "    Deletes the alias that associated the specified address\n"
            "    with a mailbox.\n"
        );
    }
    else if ( a == "setacl" ) {
        fprintf(
            stderr,
            "  setacl -- Manipulate permissions on a mailbox.\n\n"
            "    Synopsis: setacl [-d] <mailbox> <identifier> <rights>\n\n"
            "    Assigns the specified rights to the given identifier on the\n"
            "    mailbox. If the rights begin with + or -, the specified rights\n"
            "    are added to or subtracted from the existing rights; otherwise,\n"
            "    the rights are set to exactly those given.\n\n"
            "    With -d, the identifier's rights are deleted altogether.\n\n"
            "    A summary of the changes made is displayed when the operation\n"
            "    completes.\n"
        );
    }
    else if ( a == "undelete" ) {
        fprintf(
            stderr,
            "  undelete -- Restore a message that has been deleted.\n\n"
            "    Synopsis: undelete <mailbox> <search>\n\n"
            "    Searches for deleted messages in the specified mailbox and\n"
            "    restores those that match the search.\n"
            "    Messages can be restored after an IMAP EXPUNGE or POP3 DELE\n"
            "    until aox vacuum permanently removes them %d days later.\n",
            Configuration::scalar( Configuration::UndeleteTime )
        );
    }
    else if ( a == "vacuum" ) {
        fprintf(
            stderr,
            "  vacuum -- Perform routine maintenance.\n\n"
            "    Synopsis: aox vacuum\n\n"
            "    Permanently deletes messages that were marked for deletion\n"
            "    more than a certain number of days ago (cf. undelete-time)\n"
            "    and removes any bodyparts that are no longer used.\n\n"
            "    This is not a replacement for running VACUUM ANALYSE on the\n"
            "    database (either with vaccumdb or via autovacuum).\n\n"
            "    This command should be run (we suggest daily) via crontab.\n"
        );
    }
    else if ( a == "anonymise" ) {
        fprintf(
            stderr,
            "  anonymise -- Anonymise a named mail message.\n\n"
            "    Synopsis: aox anonymise filename\n\n"
            "    Reads a mail message from the named file, obscures most or\n"
            "    all content and prints the result on stdout. The output\n"
            "    resembles the original closely enough to be used in a bug\n"
            "    report.\n"
        );
    }
    else if ( a == "check" ) {
        fprintf(
            stderr,
            "  check config - Check that the configuration is sane.\n\n"
            "    Synopsis: aox check config\n\n"
            "    Reads the configuration and reports any problems it finds.\n"
        );
    }
    else if ( a == "grant" && b == "privileges" ) {
        fprintf(
            stderr,
            "  grant privileges - Grant required privileges to db-user.\n\n"
            "    Synopsis: aox grant privileges username\n\n"
            "    Makes sure that the named user has all the right permissions\n"
            "    needed by db-user (i.e. an unprivileged user), and no more.\n"
        );
    }
    else if ( a == "reparse" ) {
        fprintf(
            stderr,
            "  reparse - Retry previously-stored unparsable messages.\n\n"
            "    Synopsis: aox reparse\n\n"
            "    Looks for messages that \"arrived but could not be stored\",\n"
            "    and tries to reparse them with parsing workarounds added more\n"
            "    recently. If it succeeds, the new messages are injected.\n"
        );
    }
    else if ( a == "add" ) {
        fprintf(
            stderr,
            "\"aox add\" may be followed by: user, mailbox, alias.\n"
            "See e.g. \"aox help add user\" for more.\n"
        );
    }
    else if ( a == "list" ) {
        fprintf(
            stderr,
            "\"aox list\" may be followed by: users, mailboxes, aliases, "
            "rights.\n"
            "See e.g. \"aox help list users\" for more.\n"
        );
    }
    else if ( a == "delete" ) {
        fprintf(
            stderr,
            "\"aox delete\" may be followed by: user, mailbox, alias.\n"
            "See e.g. \"aox help delete user\" for more.\n"
        );
    }
    else if ( a == "change" ) {
        fprintf(
            stderr,
            "\"aox change\" may be followed by: username, password, address.\n"
            "See e.g. \"aox help change password\" for more.\n"
        );
    }
    else if ( a == "show" ) {
        fprintf(
            stderr,
            "\"aox show\" may be followed by: status, build, config, schema, "
            "counts.\n"
            "See e.g. \"aox help show status\" for more.\n"
        );
    }
    else if ( a == "commands" ) {
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
            "\n"
            "    show schema        -- Displays the existing schema revision.\n"
            "    upgrade schema     -- Upgrades an older schema to work with\n"
            "                          the current server.\n"
            "    update database    -- Updates the database contents, if the\n"
            "                          current server needs to.\n"
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
            "    vacuum             -- Permanently remove deleted messages.\n"
            "    anonymise          -- Anonymise a message for a bug report.\n"
            "\n"
            "  Use \"aox help command name\" for more specific help.\n"
        );
    }
    else {
        fprintf(
            stderr,
            "  aox -- A command-line interface to Archiveopteryx.\n\n"
            "    Synopsis: aox <verb> <noun> [options] [arguments]\n\n"
            "    Use \"aox help commands\" for a list of commands.\n"
            "    Use \"aox help start\" for help with \"start\".\n"
        );
    }

    finish();
}
