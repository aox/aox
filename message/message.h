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
    Message( const String &, bool );

    bool valid() const;
    String error() const;
    bool strict() const;

    String rfc822() const;

    Header * header() const;

    void setUid( uint );
    uint uid() const;

    void setMailbox( Mailbox * );
    Mailbox * mailbox() const;

    class BodyPart * bodyPart( const String & ) const;
    String partNumber( class BodyPart * ) const;

    List<BodyPart> * bodyParts() const;

    void setInternalDate( uint );
    uint internalDate() const;
    void setRfc822Size( uint );
    uint rfc822Size() const;

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
    void parseMultipart( uint, uint, const String &, const String &, bool,
                         const String & );
    void parseBodypart( uint, uint, const String &, Header *,
                        const String & );
    Header * header( uint &, uint, const String &, Header::Mode );

private:
    class MessageData * d;
    friend class MessageHeaderFetcher;
    friend class MessageBodyFetcher;
};


class BodyPart {
public:
    BodyPart();

    Header * header() const;
    ContentType * contentType() const;
    ContentTransferEncoding::Encoding encoding() const;
    String data() const;
    UString text() const;
    String partNumber() const;
    Message * rfc822() const;

private:
    class BodyPartData * d;
    friend class Message;
    friend class MessageData;
    friend class MessageHeaderFetcher;
    friend class MessageBodyFetcher;
};


class MessageHeaderFetcher: public EventHandler {
public:
    MessageHeaderFetcher( Message *, EventHandler * );

    void execute();

private:
    class MessageHeaderFetcherData * d;

    static class PreparedStatement * ps;
};


class MessageBodyFetcher: public EventHandler {
public:
    MessageBodyFetcher( Message *, EventHandler * );

    void execute();

private:
    class MessageBodyFetcherData * d;

    static class PreparedStatement * ps;
};


#endif
