// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef INJECTOR_H
#define INJECTOR_H

#include "message.h"
#include "event.h"
#include "list.h"

class Query;
class Header;
class Address;
class Mailbox;
class Bodypart;
class Annotation;


class InjectableMessage
    : public Message
{
public:
    InjectableMessage();

    void setUid( Mailbox *, uint );
    uint uid( Mailbox * ) const;

    void setModSeq( Mailbox *, int64 );
    int64 modSeq( Mailbox * ) const;

    StringList * flags( Mailbox * ) const;
    void setFlags( Mailbox *, const StringList * );
    List<Annotation> * annotations( Mailbox * ) const;
    void setAnnotations( Mailbox *, List<Annotation> * );

    List<Mailbox> * mailboxes() const;

    static InjectableMessage * wrapUnparsableMessage( const String &,
                                                      const String &,
                                                      const String &,
                                                      const String & = "" );
private:
    class InjectableMessageData * d;
};


class Injector
    : public EventHandler
{
public:
    Injector( EventHandler * );

    void execute();

    bool done() const;
    bool failed() const;
    String error() const;

    void addInjection( List<InjectableMessage> * );
    void addDelivery( Message *, Address *, List<Address> * );

private:
    class InjectorData * d;

    static void setup();

    void next();
    void findMessages();
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
    void addMailbox( Query *, InjectableMessage *, Mailbox * );
    uint addFlags( Query *, InjectableMessage *, Mailbox * );
    uint addAnnotations( Query *, InjectableMessage *, Mailbox * );
    void logDescription();
    void announce();
    Query * selectNextvals( const String &, uint );

    uint internalDate( Mailbox *, Message * ) const;
};



#endif
