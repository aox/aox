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

    void setFlags( const StringList & );
    void setAnnotations( const List<Annotation> * );
    void setDeliveryAddresses( List<Address> * );
    void setSender( Address * );

    bool done() const;
    bool failed() const;
    String error() const;
    void execute();

    uint uid( Mailbox * ) const;
    int64 modSeq( Mailbox * ) const;

    Message * message() const;

private:
    class InjectorData *d;

    static void setup();

    void finish();
    void selectUids();
    void selectMessageId();
    void resolveAddressLinks();
    void buildLinksForHeader( Header *, const String & );
    void buildFieldLinks();
    void insertPartNumber( Query *, uint, const String &,
                           int = -1, int = -1, int = -1 );
    void setupBodyparts();
    void insertMessages();
    void insertDeliveries();
    void linkBodyparts();
    void linkHeaderFields();
    void linkAddresses();
    void linkDates();
    void createFlags();
    void createAnnotationNames();
    void createFields();
    void linkFlags();
    void linkAnnotations();
    void handleWrapping();
    void logMessageDetails();
    void announce();

    uint internalDate( Mailbox *, Message * ) const;
};


#endif
