// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef INJECTOR_H
#define INJECTOR_H

#include "event.h"
#include "list.h"


class Query;
class Header;
class Message;
class Mailbox;
class Bodypart;


class Injector
    : public EventHandler
{
public:
    Injector( const Message *, SortedList< Mailbox > *, EventHandler * );
    virtual ~Injector();

    bool done() const;
    bool failed() const;
    String error() const;
    void execute();

    void announce();
    uint uid( Mailbox * ) const;

private:
    class InjectorData *d;

    static void setup();

    void selectUids();
    void buildAddressLinks();
    void buildLinksForHeader( Header *, const String & );
    void buildFieldLinks();
    void insertPartNumber( int, int, const String &,
                           int = -1, int = -1, int = -1 );
    void insertBodyparts();
    void insertBodypart( Bodypart *, bool, List< Query > *,
                         List< Query > * );
    void insertMessages();
    void linkBodyparts();
    void linkHeaderFields();
    void linkAddresses();
    void logMessageDetails();
};


#endif
