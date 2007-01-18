// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef INJECTOR_H
#define INJECTOR_H

#include "event.h"
#include "list.h"
#include "dict.h"


class Query;
class Header;
class Address;
class Mailbox;
class Message;
class Bodypart;
class StringList;
class Annotation;


class Injector
    : public EventHandler
{
public:
    Injector( Message *, EventHandler * );
    virtual ~Injector();

    enum State {
        Inactive, InsertingBodyparts, SelectingUids, InsertingMessages,
        LinkingFields, LinkingFlags, LinkingAnnotations, LinkingAddresses,
        
        AwaitingCompletion, Done
    };

    void setMailbox( Mailbox * );
    void setMailboxes( SortedList<Mailbox> * );
    void setFlags( const StringList & );
    void setAnnotations( const List<Annotation> * );
    void setDeliveryAddresses( List<Address> * );
    void setSender( Address * );

    bool done() const;
    bool failed() const;
    String error() const;
    void execute();

    void announce();
    uint uid( Mailbox * ) const;

    Message * message() const;

    SortedList<Mailbox> * mailboxes() const;

private:
    class InjectorData *d;

    static void setup();

    void finish();
    void selectUids();
    void resolveAddressLinks();
    void buildLinksForHeader( Header *, const String & );
    void buildFieldLinks();
    void insertPartNumber( Query *, int, int, const String &,
                           int = -1, int = -1, int = -1 );
    void insertBodyparts();
    void insertBodypart( Bodypart *, bool, bool, List< Query > * );
    void insertMessages();
    void insertDeliveries();
    void linkBodyparts();
    void linkHeaderFields();
    void linkAddresses();
    void linkDates();
    void createFlags();
    void createAnnotationNames();
    void linkFlags();
    void linkAnnotations();
    void logMessageDetails();

    uint internalDate( Message * ) const;
};


#endif
