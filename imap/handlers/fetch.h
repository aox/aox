// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FETCH_H
#define FETCH_H

#include "command.h"


class Query;
class Header;
class Section;
class Message;
class Bodypart;
class Multipart;
class ImapParser;
class Transaction;


class Fetch
    : public Command
{
public:
    Fetch( bool = false );
    Fetch( bool, bool, const IntegerSet &, int64, IMAP *, Transaction * );

    void parse();
    void execute();

    void parseAttribute( bool );
    static Section * parseSection( ImapParser *, bool = false );
    static EString sectionData( Section *, Message * );
    EString flagList( uint );
    EString annotation( class User *, uint,
                       const EStringList &, const EStringList & );

    EString makeFetchResponse( Message *, uint, uint );

    Message * message( uint ) const;
    void forget( uint );

private:
    void parseFetchModifier();
    void parseBody( bool );
    void parseAnnotation();
    void sendFetchQueries();
    void sendFlagQuery();
    void sendAnnotationsQuery();
    void sendModSeqQuery();
    EString dotLetters( uint, uint );
    EString internalDate( Message * );
    EString envelope( Message * );
    EString bodyStructure( Multipart *, bool );
    EString singlePartStructure( Multipart *, bool );

    void pickup();

    void enqueue( Query * q );

private:
    class FetchData * d;
};


class ImapFetchResponse
    : public ImapResponse
{
public:
    ImapFetchResponse( ImapSession *, Fetch *, uint );
    EString text() const;
    void setSent();

private:
    Fetch * f;
    uint u;
};


#endif
