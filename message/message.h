#ifndef MESSAGE_H
#define MESSAGE_H

#include "string.h"
#include "ustring.h"
#include "header.h"
#include "mimefields.h"
#include "event.h"


class Mailbox;


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

private:
    void parseMultipart( uint, uint, const String &, const String & );
    void parseBodypart( uint, uint, const String &, Header * );
    Header * header( uint &, uint, const String &, Header::Mode );

private:
    class MessageData * d;
    friend class MessageHeaderFetcher;
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
