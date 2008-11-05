// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FETCH_H
#define FETCH_H

#include "command.h"


class Header;
class Section;
class Message;
class Bodypart;
class Multipart;
class ImapParser;


class Fetch
    : public Command
{
public:
    Fetch( bool = false );
    Fetch( bool, bool, const MessageSet &, int64, IMAP * );

    void parse();
    void execute();

    void parseAttribute( bool );
    static Section * parseSection( ImapParser *, bool = false );
    static String sectionData( Section *, Message * );
    String flagList( uint );
    String annotation( class User *, uint,
                       const StringList &, const StringList & );

    String makeFetchResponse( Message *, uint, uint );

    Message * message( uint ) const;
    void forget( uint );

private:
    void parseFetchModifier();
    void parseBody( bool );
    void parseAnnotation();
    void sendFetchQueries();
    void sendFlagQuery();
    void sendAnnotationsQuery();
    String dotLetters( uint, uint );
    String internalDate( Message * );
    String envelope( Message * );
    String bodyStructure( Multipart *, bool );
    String singlePartStructure( Multipart *, bool );

    void pickup();

private:
    class FetchData * d;
};


class ImapFetchResponse
    : public ImapResponse
{
public:
    ImapFetchResponse( ImapSession *, Fetch *, uint );
    String text() const;
    void setSent();

private:
    Fetch * f;
    uint u;
};


#endif
