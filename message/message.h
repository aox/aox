// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MESSAGE_H
#define MESSAGE_H

#include "string.h"
#include "ustring.h"
#include "header.h"
#include "mimefields.h"
#include "event.h"


class Mailbox;
class Flag;


class Message {
public:
    Message();
    Message( const String & );

    bool valid() const;
    String error() const;

    String rfc822() const;

    Header * header() const;

    void setUid( uint );
    uint uid() const;

    void setMailbox( Mailbox * );
    Mailbox * mailbox() const;

    class BodyPart * bodyPart( uint ) const;
    class BodyPart * bodyPart( const String &, bool create = false );
    String partNumber( class BodyPart * ) const;

    List<BodyPart> * bodyParts() const;

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

    List<Flag> * customFlags() const;

    bool hasCustomFlags() const;
    bool hasHeaders() const;
    bool hasBodies() const;

    void fetchCustomFlags( EventHandler * );
    void fetchHeaders( EventHandler * );
    void fetchBodies( EventHandler * );

private:
    static Header * header( uint &, uint, const String &, Header::Mode );

private:
    class MessageData * d;
    friend class MessageBodyFetcher;
    friend class MessageFlagFetcher;
    friend class MessageHeaderFetcher;
    friend class BodyPart;
};


class BodyPart {
public:
    BodyPart();

    Header * header() const;
    ContentType * contentType() const;
    ContentTransferEncoding::Encoding encoding() const;
    String data() const;
    UString text() const;
    Message * rfc822() const;
    
    void setNumBytes( uint );
    uint numBytes() const;
    void setNumLines( uint );
    uint numLines() const;

private:
    static void parseMultiPart( uint, uint, const String &,
                                const String &, bool,
                                List<BodyPart> *,
                                String & );
    static BodyPart * parseBodyPart( uint, uint, const String &, Header *,
                                     String & );

private:
    class BodyPartData * d;
    friend class Message;
    friend class MessageData;
    friend class MessageHeaderFetcher;
    friend class MessageBodyFetcher;
};


#endif
