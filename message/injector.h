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
class StringList;


class Injector
    : public EventHandler
{
public:
    Injector( Message *, SortedList< Mailbox > *, EventHandler *,
              const StringList & flags );
    virtual ~Injector();

    enum State {
        Inactive, InsertingBodyparts, SelectingUids, InsertingMessages,
        LinkingFields, LinkingFlags, LinkingAddresses,
        
        AwaitingCompletion, Done
    };

    bool done() const;
    bool failed() const;
    String error() const;
    void execute();

    void announce();
    uint uid( Mailbox * ) const;

    Message * message() const;

    class DSN * dsn();

private:
    class InjectorData *d;

    static void setup();

    void finish();
    void selectUids();
    void buildAddressLinks();
    void buildLinksForHeader( Header *, const String & );
    void buildFieldLinks();
    void insertPartNumber( Query *, int, int, const String &,
                           int = -1, int = -1, int = -1 );
    void insertBodyparts();
    void insertBodypart( Bodypart *, bool, bool, List< Query > * );
    void insertMessages();
    void linkBodyparts();
    void linkHeaderFields();
    void linkAddresses();
    void linkDates();
    void createFlags();
    void linkFlags();
    void logMessageDetails();
};


#endif
