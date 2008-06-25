// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "aoxcommand.h"

#include "list.h"
#include "stringlist.h"
#include "configuration.h"
#include "eventloop.h"
#include "database.h"
#include "scope.h"

#include "users.h"
#include "stats.h"
#include "queue.h"
#include "search.h"
#include "aliases.h"
#include "servers.h"
#include "updatedb.h"
#include "anonymise.h"
#include "mailboxes.h"
#include "undelete.h"
#include "reparse.h"
#include "rights.h"
#include "views.h"
#include "help.h"
#include "db.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>


class AoxCommandData
    : public Garbage
{
public:
    AoxCommandData()
        : args( 0 ), done( false ), status( 0 ), choresDone( false )
    {
        uint i = 0;
        while ( i < 256 )
            options[i++] = 0;
    }

    StringList * args;
    int options[256];
    bool done;
    int status;
    bool choresDone;

    class ChoresDoneHelper
        : public EventHandler
    {
    public:
        ChoresDoneHelper( bool * cd, EventHandler * h )
            : EventHandler(), v( cd ), e( h )
        {
            Database::notifyWhenIdle( this );
        }
        void execute() { *v = true; e->execute(); }

        bool * v;
        EventHandler * e;
    };

    class FinishHelper
        : public EventHandler
    {
    public:
        FinishHelper() { Database::notifyWhenIdle( this ); }
        void execute() { EventLoop::shutdown(); }
    };
};


/*! \class AoxCommand aoxcommand.h
    A base class for any bin/aox commands that need callbacks.
*/

/*! Creates a new AoxCommand object with arguments from \a args. */

AoxCommand::AoxCommand( StringList * args )
    : d( new AoxCommandData )
{
    d->args = args;
    (void)new AoxCommandData::ChoresDoneHelper( &d->choresDone, this );
}


/*! Returns true only if all startup queries have been finished. Used
    by subclasses to determine when their execute() can proceed with
    their work after, e.g. waiting for "Mailbox::setup()" to complete.
*/

bool AoxCommand::choresDone()
{
    return d->choresDone;
}


static String next( StringList * sl )
{
    if ( sl->isEmpty() )
        return "";
    return *sl->shift();
}


/*! Returns the next argument, or an empty string if there are no more
    arguments.
*/

String AoxCommand::next()
{
    return ::next( d->args );
}


/*! Parses and removes a series of adjacent command-line options. opt()
    can be used to determine the presence and number of these options.
*/

void AoxCommand::parseOptions()
{
    StringList::Iterator it( d->args );
    while ( it ) {
        String s = *it;
        if ( s[0] != '-' )
            break;
        if ( s.length() == 2 &&
             ( ( s[1] >= '0' && s[1] <= '9' ) ||
               ( s[1] >= 'A' && s[1] <= 'Z' ) ||
               ( s[1] >= 'a' && s[1] <= 'z' ) ) )
            d->options[(int)s[1]]++;
        else
            error( "Bad option name: " + s.quoted() );
        d->args->take( it );
    }
}


/*! This function is used by subclasses that do their own option
    parsing. It increments the count of the option \a c, which is
    returned by opt().
*/

void AoxCommand::setopt( char c )
{
    d->options[(int)c]++;
}


/*! Returns the number of times the option \a c appeared in the command
    line arguments, as determined by parseOptions().
*/

uint AoxCommand::opt( char c )
{
    return d->options[(int)c];
}


/*! This function is used to assert that all arguments have been parsed,
    and it exits with an error() if that is not true.
*/

void AoxCommand::end()
{
    if ( d->args->isEmpty() )
        return;
    error( "Unexpected argument: " + next() );
}


/*! Prints the error message \a s and exits with an error status. */

void AoxCommand::error( const String & s )
{
    fprintf( stderr, "aox: %s\n", s.cstr() );
    exit( -1 );
}


/*! This function is provided as a convenience to subclasses that need
    to call Database::setup(). If \a owner is true, then the database
    connection is made as AOXSUPER instead of the default, AOXUSER.
*/

void AoxCommand::database( bool owner )
{
    Database::User l( Database::DbUser );
    if ( owner )
        l = Database::DbOwner;
    Database::setup( 1, l );
}


/*! This function is used by subclasses to signal the end of their
    execution. After this function is called, done() returns true,
    and status() returns \a status (which is 0 by default).
*/

void AoxCommand::finish( int status )
{
    d->done = true;
    d->status = status;
    if ( Database::idle() )
        EventLoop::shutdown();
    else
        (void)new AoxCommandData::FinishHelper;
}


/*! Returns true if this command has called finish(). */

bool AoxCommand::done() const
{
    return d->done;
}


/*! Returns the integer status of this command, as set using finish().
    This value is meaningful only if the command is done(). It is used
    as the aox exit status.
*/

int AoxCommand::status() const
{
    return d->status;
}


/*! Takes a string \a s with shell-style wildcards (*, ?) and returns an
    equivalent string with SQL-style wildcards (%, _) suitable for use
    in a LIKE clause.
*/

UString AoxCommand::sqlPattern( const UString & s )
{
    UString p;

    uint i = 0;
    while ( s[i] ) {
        if ( s[i] == '*' )
            p.append( '%' );
        else if ( s[i] == '?' )
            p.append( '_' );
        else
            p.append( s[i] );
        i++;
    }

    return p;
}


/*! Returns true if the username \a s is valid (for use by aox create
    user and similar commands). Returns false if \a s is invalid or a
    reserved username.
*/

bool AoxCommand::validUsername( const UString & s )
{
    uint i = 0;
    while ( i < s.length() &&
            ( ( s[i] >= '0' && s[i] <= '9' ) ||
              ( s[i] >= 'a' && s[i] <= 'z' ) ||
              ( s[i] >= 'Z' && s[i] <= 'Z' ) ||
              ( s[i] == '@' || s[i] == '.' ||
                s[i] == '-' || s[i] == '_' ) ) )
        i++;
    if ( i < s.length() ||
         s == "anyone" ||
         s == "group" ||
         s == "user" )
    {
        return false;
    }
    return true;
}


/*! Issues a prompt containing \a s and returns a password (of up to 128
    characters) read from the console.
*/

String AoxCommand::readPassword( const String & s )
{
    char passwd[128];
    struct termios term;
    struct termios newt;

    if ( tcgetattr( 0, &term ) < 0 )
        error( "Couldn't get terminal attributes (-" + fn( errno ) + ")." );
    newt = term;
    newt.c_lflag |= ECHONL;
    newt.c_lflag &= ~(ECHO|ISIG);
    if ( tcsetattr( 0, TCSANOW, &newt ) < 0 )
        error( "Couldn't set terminal attributes (-" + fn( errno ) + ")." );

    printf( "%s ", s.cstr() );
    fgets( passwd, 128, stdin );
    tcsetattr( 0, TCSANOW, &term );

    String p( passwd );
    p.truncate( p.length()-1 );
    return p;
}


/*! Prompts for and reads a password, then prompts for the password to
    be re-entered. If the two do not match, it is treated as an error.
    If they match, the value is returned.
*/

String AoxCommand::readNewPassword()
{
    String s = readPassword( "Password:" );
    String t = readPassword( "Retype password:" );

    if ( s != t )
        error( "Passwords do not match." );
    return s;
}


static void bad( const String &verb, const String &noun, const String &ok )
{
    if ( noun.isEmpty() )
        fprintf( stderr, "aox %s: No argument supplied.\n",
                 verb.cstr() );
    else if ( !ok.isEmpty() )
        fprintf( stderr, "aox %s: Unknown argument: %s (try %s).\n",
                 verb.cstr(), noun.cstr(), ok.cstr() );
    else
        fprintf( stderr, "aox %s: Unknown argument: %s.\n",
                 verb.cstr(), noun.cstr() );
    exit( -1 );
}


/*! Creates an AoxCommand object to handle the command described by
    \a args, and returns a pointer to it (or 0 if it failed to find
    a recognisable command).
*/

AoxCommand * AoxCommand::create( StringList * args )
{
    AoxCommand * cmd = 0;

    if ( args->isEmpty() )
        return 0;

    String verb( ::next( args ).lower() );
    if ( verb == "add" || verb == "new" )
        verb = "create";
    else if ( verb == "del" || verb == "remove" )
        verb = "delete";

    if ( verb == "start" ) {
        cmd = new Start( args );
    }
    else if ( verb == "stop" ) {
        cmd = new Stop( args );
    }
    else if ( verb == "restart" ) {
        cmd = new Restart( args );
    }
    else if ( verb == "show" ) {
        String noun = ::next( args ).lower();
        if ( noun == "status" )
            cmd = new ShowStatus( args );
        else if ( noun == "build" )
            cmd = new ShowBuild( args );
        else if ( noun == "cf" || noun == "configuration" )
            cmd = new ShowConfiguration( args );
        else if ( noun == "schema" )
            cmd = new ShowSchema( args );
        else if ( noun == "counts" )
            cmd = new ShowCounts( args );
        else if ( noun == "queue" )
            cmd = new ShowQueue( args );
        else if ( noun == "search" )
            cmd = new ShowSearch( args );
        else
            bad( verb, noun,
                 "status, build, cf, schema, counts, queue, search" );
    }
    else if ( verb == "upgrade" ) {
        String noun = ::next( args ).lower();
        if ( noun == "schema" )
            cmd = new UpgradeSchema( args );
        else
            bad( verb, noun, "schema" );
    }
    else if ( verb == "update" ) {
        String noun = ::next( args ).lower();
        if ( noun == "database" )
            cmd = new UpdateDatabase( args );
        else
            bad( verb, noun, "database" );
    }
    else if ( verb == "list" || verb == "ls" ) {
        String noun = ::next( args ).lower();
        if ( noun == "users" )
            cmd = new ListUsers( args );
        else if ( noun == "mailboxes" )
            cmd = new ListMailboxes( args );
        else if ( noun == "aliases" )
            cmd = new ListAliases( args );
        else if ( noun == "rights" )
            cmd = new ListRights( args );
        else
            bad( verb, noun, "users, mailboxes, aliases, rights" );
    }
    else if ( verb == "create" || verb == "delete" ) {
        String noun = ::next( args ).lower();
        if ( verb == "create" && noun == "user" )
            cmd = new CreateUser( args );
        else if ( verb == "delete" && noun == "user" )
            cmd = new DeleteUser( args );
        else if ( verb == "create" && noun == "mailbox" )
            cmd = new CreateMailbox( args );
        else if ( verb == "delete" &&
                  ( noun == "mailbox" || noun == "view" ) )
            cmd = new DeleteMailbox( args );
        else if ( verb == "create" && noun == "alias" )
            cmd = new CreateAlias( args );
        else if ( verb == "delete" && noun == "alias" )
            cmd = new DeleteAlias( args );
        else if ( verb == "create" && noun == "view" )
            cmd = new CreateView( args );
        else
            bad( verb, noun, "user, mailbox, alias, view" );
    }
    else if ( verb == "change" ) {
        String noun = ::next( args ).lower();
        if ( noun == "password" )
            cmd = new ChangePassword( args );
        else if ( noun == "username" )
            cmd = new ChangeUsername( args );
        else if ( noun == "address" )
            cmd = new ChangeAddress( args );
        else
            bad( verb, noun, "password, username, address" );
    }
    else if ( verb == "check" ) {
        String noun = ::next( args ).lower();
        if ( noun == "config" )
            cmd = new CheckConfig( args );
        else
            bad( verb, noun, "config" );
    }
    else if ( verb == "grant" ) {
        String noun = ::next( args ).lower();
        if ( noun == "privileges" )
            cmd = new GrantPrivileges( args );
        else
            bad( verb, noun, "privileges" );
    }
    else if ( verb == "setacl" ) {
        cmd = new SetAcl( args );
    }
    else if ( verb == "undelete" ) {
        cmd = new Undelete( args );
    }
    else if ( verb == "vacuum" ) {
        cmd = new Vacuum( args );
    }
    else if ( verb == "anonymise" ) {
        cmd = new Anonymise( args );
    }
    else if ( verb == "reparse" ) {
        cmd = new Reparse( args );
    }
    else {
        if ( verb != "help" )
            args->prepend( new String( verb ) );
        cmd = new Help( args );
    }

    return cmd;
}
