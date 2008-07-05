// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef INJECTOR_H
#define INJECTOR_H

#include "event.h"
#include "list.h"

class Query;
class Header;
class Address;
class Mailbox;
class Message;
class Bodypart;


class Injector
    : public EventHandler
{
public:
    Injector( Message *, EventHandler * );
    Injector( List<Message> *, EventHandler * );

    void execute();

    bool done() const;
    bool failed() const;
    String error() const;

    void addDelivery( Address *, List<Address> * );
    void addDelivery( Message *, Address *, List<Address> * );

private:
    class InjectorData * d;

    static void setup();

    void next();
    void findDependencies();
    void updateAddresses( List<Address> * );
    void createDependencies();
    void insertBodyparts();
    void addBodypartRow( Bodypart * );
    void selectMessageIds();
    void selectUids();
    void insertMessages();
    void insertDeliveries();
    void addPartNumber( Query *, uint, const String &, Bodypart * = 0 );
    void addHeader( Query *, Query *, Query *, uint, const String &, Header * );
    void addMailbox( Query *, Message *, Mailbox * );
    uint addFlags( Query *, Message *, Mailbox * );
    uint addAnnotations( Query *, Message *, Mailbox * );
    void logDescription();
    void announce();

    uint internalDate( Mailbox *, Message * ) const;
};


#endif
