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


class Injectee
    : public Message
{
public:
    Injectee();

    void setUid( Mailbox *, uint );
    uint uid( Mailbox * ) const;

    void setModSeq( Mailbox *, int64 );
    int64 modSeq( Mailbox * ) const;

    StringList * flags( Mailbox * ) const;
    void setFlags( Mailbox *, const StringList * );
    List<Annotation> * annotations( Mailbox * ) const;
    void setAnnotations( Mailbox *, List<Annotation> * );

    List<Mailbox> * mailboxes() const;

    static Injectee * wrapUnparsableMessage( const String &,
                                                      const String &,
                                                      const String &,
                                                      const String & = "" );
private:
    class InjecteeData * d;
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

    void addInjection( List<Injectee> * );
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
    void addMailbox( Query *, Injectee *, Mailbox * );
    uint addFlags( Query *, Injectee *, Mailbox * );
    uint addAnnotations( Query *, Injectee *, Mailbox * );
    void logDescription();
    void cache();
    void announce();
    Query * selectNextvals( const String &, uint );

    uint internalDate( Message * ) const;
};



#endif
