// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef INJECTOR_H
#define INJECTOR_H

#include "header.h"
#include "event.h"
#include "list.h"

class Message;
class Mailbox;


class Injector
    : public EventHandler
{
public:
    Injector( const Message *, SortedList< Mailbox > *, EventHandler * );
    virtual ~Injector();

    bool done() const;
    bool failed() const;
    void execute();

    static void setup();

    uint uid( Mailbox * ) const;

private:
    class InjectorData *d;

    void selectUids();
    void buildAddressLinks();
    void buildLinksForHeader( Header *, const String & );
    void buildFieldLinks();
    void insertPartNumber( int, int, const String &, int );
    void insertBodyparts();
    void insertMessages();
    void linkBodyparts();
    void linkHeaderFields();
    void linkAddresses();
    void logMessageDetails();
};


#endif
