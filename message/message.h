// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MESSAGE_H
#define MESSAGE_H

#include "multipart.h"
#include "string.h"
#include "ustring.h"
#include "header.h"
#include "mimefields.h"
#include "event.h"


class Bodypart;
class Mailbox;
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

    void setMailbox( Mailbox * );
    Mailbox * mailbox() const;

    Bodypart * bodypart( const String &, bool create = false );
    String partNumber( Bodypart * ) const;

    List<Bodypart> * allBodyparts() const;

    void setRfc822Size( uint );
    uint rfc822Size() const;
    void setInternalDate( uint );
    uint internalDate() const;

    enum BuiltinFlag {
        AnsweredFlag,
        DeletedFlag,
        DraftFlag,
        FlaggedFlag,
        SeenFlag // THIS GOES LAST
    };

    bool flag( BuiltinFlag ) const;
    void setFlag( BuiltinFlag, bool );

    List<Flag> * extraFlags() const;

    bool hasExtraFlags() const;
    bool hasHeaders() const;
    bool hasBodies() const;

    void fetchExtraFlags( EventHandler * );
    void fetchHeaders( EventHandler * );
    void fetchBodies( EventHandler * );

private:
    static Header * parseHeader( uint &, uint, const String &, Header::Mode );

private:
    class MessageData * d;
    friend class Bodypart;
    friend class MessageBodyFetcher;
    friend class MessageFlagFetcher;
    friend class MessageHeaderFetcher;
};


class Bodypart
    : public Multipart
{
public:
    Bodypart();
    Bodypart( uint, Multipart * );

    uint number() const;
    ContentType * contentType() const;
    String::Encoding encoding() const;
    String data() const;
    UString text() const;

    Message * rfc822() const;
    void setRfc822( Message * );

    void setNumBytes( uint );
    uint numBytes() const;
    void setNumLines( uint );
    uint numLines() const;

    String asText() const;

private:
    static void parseMultiPart( uint, uint, const String &,
                                const String &, bool,
                                List<Bodypart> *, Bodypart *,
                                String & );
    static Bodypart * parseBodypart( uint, uint, const String &, Header *,
                                     String & );

private:
    class BodypartData * d;
    friend class Message;
    friend class MessageData;
    friend class MessageHeaderFetcher;
    friend class MessageBodyFetcher;
};


#endif
