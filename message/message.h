// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MESSAGE_H
#define MESSAGE_H

#include "stringlist.h"
#include "multipart.h"
#include "header.h"


class EventHandler;
class Annotation;
class Bodypart;
class Mailbox;
class String;


class Message
    : public Multipart
{
public:
    Message();
    Message( const String &, Multipart * parent = 0 );

    bool valid() const;
    String error() const;
    void recomputeError();

    String rfc822() const;
    String body() const;

    void setUid( Mailbox *, uint );
    uint uid( Mailbox * ) const;

    bool inMailbox( Mailbox * ) const;
    SortedList<Mailbox> * mailboxes() const;
    void addMailboxes( List<Mailbox> * );
    void addMailbox( Mailbox * );

    void setWrapped( bool ) const;
    bool isWrapped() const;

    void setDatabaseId( uint );
    uint databaseId() const;

    bool isMessage() const;

    Bodypart * bodypart( const String &, bool create = false );
    String partNumber( Bodypart * ) const;

    List<Bodypart> * allBodyparts() const;

    void setRfc822Size( uint );
    uint rfc822Size() const;
    void setInternalDate( Mailbox *, uint );
    uint internalDate( Mailbox * ) const;
    void setModSeq( Mailbox *, uint );
    uint modSeq( Mailbox * ) const;

    StringList * flags( Mailbox * ) const;
    void setFlags( Mailbox *, const StringList * );
    void setFlag( Mailbox *, const String & );
    List<Annotation> * annotations( Mailbox * ) const;
    void setAnnotations( Mailbox *, List<Annotation> * );

    bool hasFlags( Mailbox * ) const;
    bool hasHeaders() const;
    bool hasAddresses() const;
    bool hasTrivia() const;
    bool hasBodies() const;
    bool hasAnnotations( Mailbox * ) const;
    bool hasBytesAndLines() const;
    void setFlagsFetched( Mailbox *, bool );
    void setHeadersFetched();
    void setBodiesFetched();
    void setAnnotationsFetched( Mailbox *, bool );
    void setAddressesFetched();
    void setBytesAndLinesFetched();

    void replaceAnnotation( Mailbox *, class Annotation * );

    static String baseSubject( const String & );

    static String acceptableBoundary( const String & );

    static Message * wrapUnparsableMessage( const String &,
                                            const String &,
                                            const String &,
                                            const String & = "" );
    void addMessageId();

    static Header * parseHeader( uint &, uint, const String &, Header::Mode );

private:
    void fix8BitHeaderFields();

private:
    class MessageData * d;
    friend class MessageBodyFetcher;
    friend class MessageFlagFetcher;
};


#endif
