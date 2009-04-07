// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVENOTIFY_H
#define SIEVENOTIFY_H

#include "ustring.h"
#include "estring.h"

class SieveProduction;
class SieveArgument;
class Address;


class SieveNotifier
    : public Garbage
{
};


class SieveNotifyMethod
    : public Garbage
{
public:
    SieveNotifyMethod( const UString &,
                       class SieveProduction *,
                       class SieveProduction * );

    void setFrom( const UString &, SieveArgument * );
    void setFrom( Address * );
    void setMessage( const UString &, SieveArgument * );

    SieveProduction * command() const;

    bool valid();

    enum Type {
        Mailto,
        Invalid
    };
    
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
