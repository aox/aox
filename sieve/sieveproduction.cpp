// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sieveproduction.h"

#include "sieveparser.h"
#include "stringlist.h"
#include "mailbox.h"
#include "address.h"


class SieveProductionData
    : public Garbage
{
public:
    SieveProductionData( const char * n )
        : parent( 0 ), parser( 0 ), start( 0 ), end( 0 ), name( n ) {}

    SieveProduction * parent;
    SieveParser * parser;
    uint start;
    uint end;
    const char * name;
    String error;
};


/*! \class SieveProduction sieveproduction.h

    The SieveProduction class is the common base class for
    SieveArgument, SieveCommand and the other classes that describe a
    single production in the Sieve grammar (or lexer). The "start"
    symbol is represented by SieveScript.

    SieveProduction does very little except remember where in the
    source it comes from, so errors can be reported well.
*/


/*! Constructs a SieveProduction for a production whose sieve name is
    \a name.
*/

SieveProduction::SieveProduction( const char * name )
    : Garbage(), d( new SieveProductionData( name ) )
{
}


/*! Notifies this SieveProduction that it's a child of \a parent. The
    parent() is used to construct error messages.
*/

void SieveProduction::setParent( SieveProduction * parent )
{
    d->parent = parent;
}


/*! Returns a pointer to this object's parent, or a null pointer if
    none has been set.
*/

SieveProduction * SieveProduction::parent() const
{
    return d->parent;
}


/*! This slightly hacky function records that the production was
    parsed by \a p, and \a p should also be used to report any errors
    this object might have. Could have been done as a constructor
    argument, but I've already written the constructors and I don't
    want to do all the editing.

    The initial value is 0.
*/

void SieveProduction::setParser( class SieveParser * p )
{
    d->parser = p;
}


/*! Returns the name of this production as defined in RFC 3028 section
    8.
*/

String SieveProduction::name() const
{
    return d->name;
}


/*! Notifies this SieveProduction that its parsing started at position
    \a p. The first character in the source is 0, and we count bytes,
    not lines.
*/

void SieveProduction::setStart( uint p )
{
    d->start = p;
}


/*! Returns what setStart() set, or 0. */

uint SieveProduction::start() const
{
    return d->start;
}


/*! Notifies this SieveProduction that its parsing ended at position
    \a p. The first character in the source is 0, and we count bytes,
    not lines.
*/

void SieveProduction::setEnd( uint p )
{
    d->end = p;
}


/*! Returns what setEnd() set, or 0. */

uint SieveProduction::end() const
{
    return d->end;
}


/*! Records that this production suffers from error \a e. Does nothing
    if setError has been called already. */

void SieveProduction::setError( const String & e )
{
    if ( !d->error.isEmpty() && !e.isEmpty() )
        d->error = e;
    if ( !d->error.isEmpty() && d->parser )
        d->parser->rememberBadProduction( this );
}


/*! Returns what setError() set, or an empty string if no error has
    occured.
*/

String SieveProduction::error() const
{
    return d->error;
}


/*! Returns true if \a s is the name of a supported sieve extension,
    and false if it is not. \a s must be in lower case.

*/

bool SieveProduction::supportedExtension( const String & s )
{
    if ( s == "fileinto" )
        return true;
    if ( s == "reject" )
        return true;
    return false;
}


class SieveArgumentData
    : public Garbage
{
public:
    SieveArgumentData(): number( 0 ), list( 0 ), calls( 0 ) {}
    String tag;
    uint number;
    StringList * list;
    uint calls;
};


/*! \class SieveArgument sieveproduction.h

    The SieveArgument class models the RFC 3028 "argument" production.

    Nothing prevents the user from setting both tag(), number() and
    stringList(), even though in theory exactly one should be set.
*/


SieveArgument::SieveArgument()
    : SieveProduction( "argument" ), d( new SieveArgumentData )
{
    // nothing needed
}


/*! Notifies this object that it has a tag, and that its tag is \a t.

*/

void SieveArgument::setTag( const String & t )
{
    d->tag = t;
    d->calls++;
}


/*! Returns the object's tag, or an empty string if this object
    doesn't have a tag (in which case it has a stringList(), number()
    or a nonempty error()).
*/

String SieveArgument::tag() const
{
    return d->tag;
}


/*! Notifies this object that has a number, and that its number is \a
    n.
*/

void SieveArgument::setNumber( uint n )
{
    d->number = n;
    d->calls++;
}


/*! Returns the object's number, or 0 if this object doesn't have a
    number (in which case it has a stringList(), tag() or a nonempty
    error()).
*/

uint SieveArgument::number() const
{
    return d->number;
}


/*! Notifies this object that it has a string list, and that its
    string list is \a s. If \a s is a null pointer, this function does
    nothing.
*/

void SieveArgument::setStringList( class StringList * s )
{
    if ( !s )
        return;
    d->list = s;
    d->calls++;
}


/*! Returns the object's string list, or a null pointer if this object
    doesn't have a string list (in which case it has a number(), tag()
    or a nonempty error()).

*/

class StringList * SieveArgument::stringList() const
{
    return d->list;
}


class SieveArgumentListData
    : public Garbage
{
public:
    SieveArgumentListData() {}

    List<SieveArgument> a;
    List<SieveTest> t;
};


/*! \class SieveArgumentList sieveproduction.h

    The SieveArgumentList class models the arguments production.
*/

SieveArgumentList::SieveArgumentList()
    : SieveProduction( "arguments" ), d( new SieveArgumentListData )
{
}


/*! Appands \a a to the list of arguments() kept by this object. Does
    nothing if \a a is 0.
*/

void SieveArgumentList::append( SieveArgument * a )
{
    if ( !a )
        return;
    d->a.append( a );
    a->setParent( this );
}


/*! Returns a pointer to this object's list of SieveArgument objects.
    The returned list may be empty, but the pointer is never 0.
*/

List<SieveArgument> * SieveArgumentList::arguments() const
{
    return &d->a;
}


/*! Appands \a t to the list of tests() kept by this object. Does
    nothing if \a t is 0.
*/

void SieveArgumentList::append( SieveTest * t )
{
    if ( !t )
        return;

    d->t.append( t );
    t->setParent( this );
}


/*! Returns a pointer to this object's list of SieveTest objects.
    The returned list may be empty, but the pointer is never 0.
*/

List<SieveTest> * SieveArgumentList::tests() const
{
    return &d->t;
}


class SieveBlockData
    : public Garbage
{
public:
    SieveBlockData() {}

    List<SieveCommand> c;
};


/*! \class SieveBlock sieveproduction.h

    The SieveBlock class models the RFC 3028 block.
*/


SieveBlock::SieveBlock()
    : SieveProduction( "block" ), d( new SieveBlockData )
{
}


/*! Appends \a c to this block. Does nothing if \a c is 0. */

void SieveBlock::append( class SieveCommand * c )
{
    if ( !c )
        return;

    d->c.append( c );
    c->setParent( this );
}


/*! Returns a pointer the list of commands held in this block. The
    returned pointer is never 0, but the list may be empty.
*/

List<SieveCommand> * SieveBlock::commands() const
{
    return &d->c;
}


class SieveCommandData
    : public Garbage
{
public:
    SieveCommandData(): arguments( 0 ), block( 0 ), require( false ) {}

    String identifier;
    SieveArgumentList * arguments;
    SieveBlock * block;
    bool require;
};


/*! \class SieveCommand sieveproduction.h

    The SieveCommand class models the RFC 3028 "command" production.
*/

SieveCommand::SieveCommand()
    : SieveProduction( "command" ), d( new SieveCommandData )
{
}


/*! Notifies this command that its identifier if \a i. The initial
    value is an empty string, which is not valid.
*/

void SieveCommand::setIdentifier( const String & i )
{
    d->identifier = i;
}


/*! Returns what setIdentifier() set, or an empty string if
    setIdentifier() has not been called.
*/

String SieveCommand::identifier() const
{
    return d->identifier;
}


/*! Notifies this command that \a l is a list of its arguments. Does
    nothing if \a l is a null pointer.
*/

void SieveCommand::setArguments( SieveArgumentList * l )
{
    if ( !l )
        return;

    d->arguments = l;
    l->setParent( this );
}


/*! Returns what setArguments() set, or a null pointer if
    setArguments() has not been called.
*/

SieveArgumentList * SieveCommand::arguments() const
{
    return d->arguments;
}


/*! Notifies this command that \a b is its subsidiary block. Does
    nothing if \a b is 0.
*/

void SieveCommand::setBlock( SieveBlock * b )
{
    if ( !b )
        return;

    d->block = b;
    b->setParent( this );
}


/*! Returns what setBlock() set, or 0 if setBlock() has not been
    called.

*/

SieveBlock * SieveCommand::block() const
{
    return d->block;
}


/*! Notifies this command that in this position, "require" is either
    permitted or not, depending on \a p. The initial value is false.
*/

void SieveCommand::setRequirePermitted( bool p )
{
    d->require = p;
}


class SieveTestData
    : public Garbage
{
public:
    SieveTestData(): arguments( 0 ), block( 0 ) {}

    String identifier;
    SieveArgumentList * arguments;
    SieveBlock * block;
};


/*! \class SieveTest sieveproduction.h

    The SieveTest class models the RFC 3028 "test" production.
*/

SieveTest::SieveTest()
    : SieveProduction( "command" ), d( new SieveTestData )
{
}


/*! Notifies this command that its identifier if \a i. The initial
    value is an empty string, which is not valid.
*/

void SieveTest::setIdentifier( const String & i )
{
    d->identifier = i;
}


/*! Returns what setIdentifier() set, or an empty string if
    setIdentifier() has not been called.
*/

String SieveTest::identifier() const
{
    return d->identifier;
}


/*! Notifies this command that \a l is a list of its arguments. Does
    nothing if \a l is a null pointer.
*/

void SieveTest::setArguments( SieveArgumentList * l )
{
    if ( !l )
        return;

    d->arguments = l;
    l->setParent( this );
}


/*! Returns what setArguments() set, or a null pointer if
    setArguments() has not been called.
*/

SieveArgumentList * SieveTest::arguments() const
{
    return d->arguments;
}


/*! Performs second-phase parsing of this command. Checks that its
    name is supported and that the arguments fit the command.
*/

void SieveCommand::parse()
{
    if ( identifier().isEmpty() )
        setError( "Command name is empty" );

    uint maxargs = 0;
    uint minargs = 0;
    bool addrs = false;
    bool mailboxes = false;
    bool extensions = false;
    bool test = false;

    String i = identifier().lower();
    if ( i == "if" ) {
        test = true;
        maxargs = UINT_MAX;
    } else if ( i == "require" ) {
        extensions = true;
        if ( !d->require )
            setError( "require is only permitted as the first command." );
    } else if ( i == "stop" ) {
        // nothing needed
    } else if ( i == "reject" ) {
        // nothing needed
    } else if ( i == "fileinto" ) {
        mailboxes = true;
        maxargs = UINT_MAX;
    } else if ( i == "redirect" ) {
        addrs = true;
        maxargs = UINT_MAX;
    } else if ( i == "keep" ) {
        // nothing needed
    } else if ( i == "discard" ) {
        // nothing needed
    } else {
        setError( "Command unknown: " + identifier() );
    }

    // test each condition in the same order as the variables declared
    // above

    if ( minargs &&
         ( !arguments() ||
           arguments()->arguments()->count() < minargs ) )
        setError( "Too few arguments (" +
                  fn ( arguments()->arguments()->count() ) +
                  ", minimum required is " +
                  fn ( minargs ) + ")" );

    if ( maxargs < UINT_MAX &&
         arguments() &&
         arguments()->arguments()->count() > maxargs )
        setError( "Too many arguments (" +
                  fn ( arguments()->arguments()->count() ) +
                  ", maximum allowed is " +
                  fn ( maxargs ) + ")" );

    if ( arguments() &&
         ( addrs || mailboxes || extensions ) ) {
        List<SieveArgument>::Iterator i( arguments()->arguments() );
        while ( i ) {
            SieveArgument * a = i;
            ++i;
            if ( a->number() ) {
                a->setError( "Numeric not permitted as argument to command " +
                             identifier() );
            }
            else if ( !a->tag().isEmpty() ) {
                a->setError( "Tag not permitted as argument to command " +
                             identifier() );
            }
            else if ( addrs ) {
                StringList::Iterator i( a->stringList() );
                while ( i ) {
                    AddressParser ap( *i );
                    if ( !ap.error().isEmpty() )
                        a->setError( "Each string must be an email address. "
                                     "This one is not: " + *i );
                    else if ( ap.addresses()->count() != 1 )
                        a->setError( "Each string must be 1 email address. "
                                     "This one represents " +
                                     fn ( ap.addresses()->count() ) + ": " +
                                     *i );
                    else if ( ap.addresses()->first()->type() !=
                              Address::Normal )
                        a->setError( "Each string must be an ordinary "
                                     "email address (localpart@domain). "
                                     "This one is not: " + *i +
                                     " (it represents " +
                                     ap.addresses()->first()->toString() +
                                     ")" );
                    ++i;
                }
            }
            else if ( mailboxes ) {
                StringList::Iterator i( a->stringList() );
                while ( i ) {
                    if ( !Mailbox::validName( *i ) )
                        a->setError( "Each string must be an mailbox name. "
                                     "This one is not: " + *i );
                    ++i;
                }
            }
            else if ( extensions ) {
                StringList::Iterator i( a->stringList() );
                while ( i ) {
                    if ( !supportedExtension( i->lower() ) )
                        a->setError( "Each string must be a supported "
                                     "sieve extension. "
                                     "This one is not: " + *i );
                    ++i;
                }
            }
        }
    }

    if ( test ) {
        // we must have a test and a block
        if ( !arguments() || arguments()->tests()->isEmpty() )
            setError( "Command " + identifier() +
                      " requires a test" );
        if ( !block() )
            setError( "Command " + identifier() +
                      " requires a subsidiary {..} block" );
    }
    else {
        // we cannot have a test or a block
        if ( arguments() && arguments()->tests()->isEmpty() ) {
            List<SieveTest>::Iterator i( arguments()->tests() );
            while ( i ) {
                i->setError( "Command " + identifier() +
                             " does not use tests" );
                ++i;
            }
        }
        if ( block() )
            block()->setError( "Command " + identifier() +
                               " does not use a subsidiary command block" );
    }

}
