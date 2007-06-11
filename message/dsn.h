// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DSN_H
#define DSN_H

#include "string.h"
#include "list.h"
#include "recipient.h"

class Address;
class Message;


class DSN
    : public Garbage
{
public:
    DSN();

    void setMessage( Message * );
    Message * message() const;

    void setEnvelopeId( const String & );
    String envelopeId() const;

    void setFullReport( bool );
    bool fullReport() const;

    void setReceivedFrom( const String & );
    String receivedFrom() const;

    void setArrivalDate( class Date * );
    Date * arrivalDate() const;

    List<Recipient> * recipients() const;
    void addRecipient( Recipient * );

    void setSender( Address * );
    Address * sender() const;

    Message * result() const;

    void setResultDate( class Date * );
    Date * resultDate() const;

    bool allOk() const;
    bool allFailed() const;

    String plainBody() const;
    String dsnBody() const;

    bool valid() const;

private:
    class DSNData * d;
};


#endif
