// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SIEVENOTIFY_H
#define SIEVENOTIFY_H

#include "ustring.h"
#include "estring.h"

class SieveProduction;
class SieveArgument;
class Address;


class SieveNotifyMethod
    : public Garbage
{
public:
    SieveNotifyMethod( const UString &,
                       class SieveProduction *,
                       class SieveProduction * );

    void setFrom( const UString &, SieveProduction * );
    void setFrom( Address * );
    void setMessage( const UString &, SieveProduction * );

    SieveProduction * command() const;

    bool valid();

    enum Type {
        Mailto,
        Invalid
    };

    Type type() const;

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
