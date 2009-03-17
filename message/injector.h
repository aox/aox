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

    EStringList * flags( Mailbox * ) const;
    void setFlags( Mailbox *, const EStringList * );
    List<Annotation> * annotations( Mailbox * ) const;
    void setAnnotations( Mailbox *, List<Annotation> * );

    List<Mailbox> * mailboxes() const;

    static Injectee * wrapUnparsableMessage( const EString &,
                                                      const EString &,
                                                      const EString &,
                                                      const EString & = "" );
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
    EString error() const;

    void addInjection( List<Injectee> * );
    void addDelivery( Injectee *, Address *, List<Address> * );

    void setTransaction( class Transaction * );

    void addAddress( Address * );
    uint addressId( Address * );

private:
    class InjectorData * d;

    void next();
    void createMailboxes();
    void findMessages();
    void findDependencies();
    void updateAddresses( List<Address> * );
    void createDependencies();
    void convertInReplyTo();
    void addMoreReferences();
    void convertThreadIndex();
    void insertThreadIndexes();
    void insertBodyparts();
    void addBodypartRow( Bodypart * );
    void selectMessageIds();
    void selectUids();
    void insertMessages();
    void insertDeliveries();
    void addPartNumber( Query *, uint, const EString &, Bodypart * = 0 );
    void addHeader( Query *, Query *, Query *, uint, const EString &, Header * );
    void addMailbox( Query *, Injectee *, Mailbox * );
    uint addFlags( Query *, Injectee *, Mailbox * );
    uint addAnnotations( Query *, Injectee *, Mailbox * );
    void logDescription();
    void cache();
    Query * selectNextvals( const EString &, uint );

    uint internalDate( Message * ) const;
};



#endif
