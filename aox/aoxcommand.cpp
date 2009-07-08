// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "aoxcommand.h"

#include "list.h"
#include "estringlist.h"
#include "configuration.h"
#include "eventloop.h"
#include "database.h"
#include "address.h"
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

    EStringList * args;
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

AoxCommand::AoxCommand( EStringList * args )
    : d( new AoxCommandData )
{
    d->args = args;
    (void)new AoxCommandData::ChoresDoneHelper( &d->choresDone, this );
    Allocator::addEternal( this, "the command to be run" );
}


/*! Returns true only if all startup queries have been finished. Used
    by subclasses to determine when their execute() can proceed with
    their work after, e.g. waiting for "Mailbox::setup()" to complete.
*/

bool AoxCommand::choresDone()
{
    return d->choresDone;
}


static EString next( EStringList * sl )
{
    if ( sl->isEmpty() )
        return "";
    return *sl->shift();
}


/*! Returns the list of unparsed arguments. next() takes an argument
    from the front of this list.
*/

EStringList * AoxCommand::args()
{
    return d->args;
}


/*! Returns the next argument, or an empty string if there are no more
    arguments.
*/

EString AoxCommand::next()
{
    return ::next( d->args );
}


/*! Returns the next argument as an address. Signals an error and
    exits if the next argument isn't a string or there is no next
    argument.
*/

class Address * AoxCommand::nextAsAddress()
{
    EString n = next();
    AddressParser p( n );
    p.assertSingleAddress();
    if ( !p.error().isEmpty() ) {
        error( "Invalid address: " + p.error() );
    }
    return p.addresses()->first();
}


/*! Parses and removes a series of adjacent command-line options. opt()
    can be used to determine the presence and number of these options.
*/

void AoxCommand::parseOptions()
{
    EStringList::Iterator it( d->args );
    while ( it ) {
        EString s = *it;
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

void AoxCommand::error( const EString & s )
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
              ( s[i] >= 'A' && s[i] <= 'Z' ) ||
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

EString AoxCommand::readPassword( const EString & s )
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

    EString p( passwd );
    p.truncate( p.length()-1 );
    return p;
}


/*! Prompts for and reads a password, then prompts for the password to
    be re-entered. If the two do not match, it is treated as an error.
    If they match, the value is returned.
*/

EString AoxCommand::readNewPassword()
{
    EString s = readPassword( "Password:" );
    EString t = readPassword( "Retype password:" );

    if ( s != t )
        error( "Passwords do not match." );
    return s;
}


/*! Creates an AoxCommand object to handle the command described by
    \a args, and returns a pointer to it (or 0 if it failed to find
    a recognisable command).
*/

AoxCommand * AoxCommand::create( EStringList * args )
{
    if ( args->isEmpty() )
        return 0;

    EString verb( ::next( args ).lower() );

    EString noun;
    if ( AoxCommandMap::needsNoun( verb ) )
        noun = ::next( args ).lower();

    AoxCommand * cmd = AoxCommandMap::provide( verb, noun, args );

    if ( cmd )
        return cmd;

    if ( AoxCommandMap::validVerbs()->contains( verb ) )
        fprintf( stderr, "aox %s: Valid arguments:\n%s.\n",
                 verb.cstr(),
                 AoxCommandMap::validNouns( verb )->join( ", " )
                 .wrapped( 70, "    ", "    ", false ).cstr() );
    else
        fprintf( stderr, "aox: Valid commands:\n%s.\n",
                 AoxCommandMap::validVerbs()->join( ", " )
                 .wrapped( 70, "    ", "    ", false ).cstr() );

    exit( -1 );
    return 0;
}


/*! Returns a pointer to the AoxCommand sublass which handles \a verb
    \a noun, or a null pointer if there isn't any such subclass.
*/

AoxCommand * AoxCommandMap::provide( const EString & verb,
                                     const EString & noun,
                                     EStringList * args )
{
    AoxCommandMap * m = first;
    while ( m ) {
        if ( verb == m->v && noun == m->n )
            return m->provide( args );
        m = m->x;
    }
    return 0;
}


AoxCommandMap * AoxCommandMap::first;


/*! Returns a list of valid aox commands.

*/

EStringList * AoxCommandMap::validVerbs()
{
    EStringList r;
    AoxCommandMap * m = first;
    while ( m ) {
        r.append( m->v );
        m = m->x;
    }
    r.removeDuplicates();
    return r.sorted();

}


/*! Returns a list of valid arguments for \a verb.
 */

EStringList * AoxCommandMap::validNouns( const EString & verb )
{
    EStringList r;
    AoxCommandMap * m = first;
    while ( m ) {
        if ( verb == m->v )
            r.append( m->n );
        m = m->x;
    }
    r.removeDuplicates();
    return r.sorted();
}


/*! Returns the "about" text for \a verb \a noun. */

EString AoxCommandMap::aboutCommand( const EString & verb,
                                     const EString & noun )
{
    AoxCommandMap * m = first;
    while ( m ) {
        if ( verb == m->v && noun == m->n )
            return m->a;
        m = m->x;
    }
    return "";
}


/*! Returns the brief one-line description of \a verb \a noun. */

EString AoxCommandMap::inBrief( const EString & verb, const EString & noun )
{
    AoxCommandMap * m = first;
    while ( m ) {
        if ( verb == m->v && noun == m->n )
            return m->b;
        m = m->x;
    }
    return "";
}


/*! Returns true if \a verb needs a noun, and false if it works on its
    own (as e.g. aox restart does) or doesn't exist.
*/

bool AoxCommandMap::needsNoun( const EString & verb )
{
    AoxCommandMap * m = first;
    while ( m && verb != m->v )
        m = m->x;
    if ( !m )
        return true;
    if ( *m->n )
        return true;
    return false;
}
