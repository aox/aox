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
    static String flagList( Message *, uint, class Session * );
    static String annotation( Multipart *, class User *, Mailbox * m,
                              const StringList &,
                              const StringList & );

    void trickle();

private:
    void parseFetchModifier();
    void parseBody( bool );
    void parseAnnotation();
    void sendFetchQueries();
    String dotLetters( uint, uint );
    String internalDate( Message * );
    String envelope( Message * );
    String bodyStructure( Multipart *, bool );
    String singlePartStructure( Multipart *, bool );
    void makeFetchResponse( Message *, uint, uint );

    void pickup();

private:
    class FetchData * d;
};


#endif
