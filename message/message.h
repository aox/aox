// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MESSAGE_H
#define MESSAGE_H

#include "multipart.h"
#include "header.h"


class EventHandler;
class Annotation;
class Bodypart;
class Mailbox;
class String;
class Flag;


class Message
    : public Multipart
{
public:
    Message();
    Message( const String &, Multipart * parent = 0 );

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
    void setModSeq( uint );
    uint modSeq() const;

    List<Flag> * flags() const;
    List<Annotation> * annotations() const;

    bool hasFlags() const;
    bool hasHeaders() const;
    bool hasAddresses() const;
    bool hasTrivia() const;
    bool hasBodies() const;
    bool hasAnnotations() const;
    void setFlagsFetched( bool );
    void setHeadersFetched();
    void setBodiesFetched();
    void setAnnotationsFetched();
    void setAddressesFetched();

    void replaceAnnotation( class Annotation * );

    static String baseSubject( const String & );

    static String acceptableBoundary( const String & );

    static Message * wrapUnparsableMessage( const String &,
                                            const String &,
                                            const String &,
                                            const String & = "" );

private:
    static Header * parseHeader( uint &, uint, const String &, Header::Mode );
    void fix8BitHeaderFields();

private:
    class MessageData * d;
    friend class Bodypart;
    friend class MessageBodyFetcher;
    friend class MessageFlagFetcher;
};


#endif
