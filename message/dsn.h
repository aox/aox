// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef DSN_H
#define DSN_H

#include "estring.h"
#include "list.h"
#include "recipient.h"

class Address;
class Message;
class Injectee;


class DSN
    : public Garbage
{
public:
    DSN();

    void setMessage( Message * );
    Message * message() const;

    void setEnvelopeId( const EString & );
    EString envelopeId() const;

    void setFullReport( bool );
    bool fullReport() const;

    void setReceivedFrom( const EString & );
    EString receivedFrom() const;

    void setArrivalDate( class Date * );
    Date * arrivalDate() const;

    List<Recipient> * recipients() const;
    void addRecipient( Recipient * );

    void setSender( Address * );
    Address * sender() const;

    Injectee * result() const;

    void setResultDate( class Date * );
    Date * resultDate() const;

    bool allOk() const;
    bool allFailed() const;
    bool deliveriesPending() const;

    EString plainBody() const;
    EString dsnBody() const;

    bool valid() const;

private:
    class DSNData * d;
};


#endif
