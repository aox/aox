// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef AOXCOMMAND_H
#define AOXCOMMAND_H

#include "event.h"
#include "ustring.h"

#include <string.h> // strcmp


class EStringList;


class AoxCommand
    : public EventHandler
{
public:
    AoxCommand( EStringList * );

    bool done() const;
    int status() const;

    static AoxCommand * create( EStringList * );

protected:
    EString next();
    EStringList * args();
    class Address * nextAsAddress();
    void setopt( char );
    uint opt( char );
    void parseOptions();
    void end();
    void database( bool = false );
    void error( const EString & );
    void finish( int = 0 );
    UString sqlPattern( const UString & );
    bool validUsername( const UString & );
    bool choresDone();
    EString readPassword( const EString & );
    EString readNewPassword();

private:
    class AoxCommandData * d;
};


class AoxCommandMap
// NOT a Garbage inheritor. created early, not on the heap
{
public:
    AoxCommandMap( const char * verb, const char * noun,
                   const char * brief, const char * about )
        : v( verb ), n( noun ), b( brief), a( about ), x( 0 ), c( 0 ) {
        x = first;
        first = this;
    }
    AoxCommandMap( const char * verb, const char * noun,
                   AoxCommandMap * canonical )
        : v( verb ), n( noun ),
          b( canonical->b ), a( canonical->a ),
          x( 0 ), c( canonical ) {
        x = first;
        first = this;
    }
    virtual ~AoxCommandMap() {}

    static AoxCommand * provide( const EString &, const EString &,
                                 EStringList * );

    virtual AoxCommand * provide( EStringList * ) = 0;

    static EStringList * validVerbs();
    static EStringList * validNouns( const EString & );
    static EString aboutCommand( const EString &, const EString & );
    static EString inBrief( const EString &, const EString & );
    static bool needsNoun( const EString & );

    static EStringList * aliases();

private:
    const char * v;
    const char * n;
    const char * b;
    const char * a;

    AoxCommandMap * x;

    AoxCommandMap * c;

    static AoxCommandMap * first;
};



template<class T>
class AoxFactory
    : public AoxCommandMap
{
public:
    AoxFactory( const char * verb, const char * noun,
                const char * brief, const char * about )
        : AoxCommandMap( verb, noun, brief, about ) {
        if ( !strcmp( verb, "create" ) ) {
            (void)new AoxFactory<T>( "add", noun, this );
            (void)new AoxFactory<T>( "new", noun, this );
        }
        else if ( !strcmp( verb, "delete" ) ) {
            (void)new AoxFactory<T>( "del", noun, this );
            (void)new AoxFactory<T>( "remove", noun, this );
        }
        else if ( !strcmp( verb, "list" ) ) {
            (void)new AoxFactory<T>( "ls", noun, this );
        }
    }
    AoxFactory( const char * verb, const char * noun,
                AoxFactory<T> * canonical )
        : AoxCommandMap( verb, noun, canonical ) {}
    AoxCommand * provide( EStringList * l ) { return new T( l ); }
};


#endif
