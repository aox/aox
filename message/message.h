// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MESSAGE_H
#define MESSAGE_H

#include "multipart.h"
#include "header.h"


class EventHandler;
class Bodypart;
class Mailbox;
class String;
class Flag;


class Message
    : public Multipart
{
public:
    Message();
    Message( const String & );

    bool valid() const;
    String error() const;

    String rfc822() const;
    String body() const;

    void setUid( uint );
    uint uid() const;

    void setMailbox( const Mailbox * );
    const Mailbox * mailbox() const;

    bool isMessage() const;

    Bodypart * bodypart( const String &, bool create = false );
    String partNumber( Bodypart * ) const;

    List<Bodypart> * allBodyparts() const;

    void setRfc822Size( uint );
    uint rfc822Size() const;
    void setInternalDate( uint );
    uint internalDate() const;

    List<Flag> * flags() const;

    bool hasFlags() const;
    bool hasHeaders() const;
    bool hasTrivia() const;
    bool hasBodies() const;
    bool hasAnnotations() const;
    void setFlagsFetched( bool );
    void setHeadersFetched();
    void setBodiesFetched();
    void setAnnotationsFetched();

    static String baseSubject( const String & );

private:
    static Header * parseHeader( uint &, uint, const String &, Header::Mode );

private:
    class MessageData * d;
    friend class Bodypart;
    friend class MessageBodyFetcher;
    friend class MessageFlagFetcher;
};


#endif
