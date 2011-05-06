// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SIEVENOTIFY_H
#define SIEVENOTIFY_H

#include "ustring.h"
#include "estring.h"


class SieveNotifyMethod
    : public Garbage
{
public:
    SieveNotifyMethod( const UString &,
                       class SieveProduction *,
                       class SieveProduction * );

    void setFrom( const UString &, SieveProduction * );
    void setFrom( class Address * );
    void setOwner( class Address * );
    class Address * owner() const;
    void setMessage( const UString &, class SieveProduction * );

    class SieveProduction * command() const;

    bool valid();

    enum Type {
        Mailto,
        Invalid
    };

    Type type() const;
    class Injectee * mailtoMessage() const;

    enum Reachability {
        Immediate,
        Delayed,
        Unknown
    };
    Reachability reachability() const;

private:
    class SieveNotifyMethodData * d;
    void reportError( const EString &, class SieveProduction * = 0 );

};


#endif
