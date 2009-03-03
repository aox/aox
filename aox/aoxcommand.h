// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef AOXCOMMAND_H
#define AOXCOMMAND_H

#include "event.h"
#include "ustring.h"


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

    static AoxCommand * provide( const EString &, const EString &,
                                 EStringList * );

    virtual AoxCommand * provide( EStringList * ) = 0;

    static EStringList * validVerbs();
    static EStringList * validNouns( const EString & );
    static EString aboutCommand( const EString &, const EString & );
    static EString inBrief( const EString &, const EString & );
    static bool needsNoun( const EString & );

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
        : AoxCommandMap( verb, noun, brief, about ) {}
    AoxFactory( const char * verb, const char * noun,
                AoxFactory<T> * canonical )
        : AoxCommandMap( verb, noun, canonical ) {}
    AoxCommand * provide( EStringList * l ) { return new T( l ); }
};


#endif
