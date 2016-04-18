// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef MESSAGE_H
#define MESSAGE_H

#include "estringlist.h"
#include "multipart.h"
#include "header.h"


class EventHandler;
class Bodypart;
class Mailbox;
class EString;


class Message
    : public Multipart
{
public:
    Message();

    void parse( const EString & );

    bool valid() const;
    EString error() const;
    void recomputeError();

    EString rfc822( bool ) const;
    EString body( bool ) const;

    void setWrapped( bool ) const;
    bool isWrapped() const;

    void setDatabaseId( uint );
    uint databaseId() const;

    void setThreadId( uint );
    uint threadId() const;

    bool isMessage() const;

    Bodypart * bodypart( const EString &, bool create = false );
    EString partNumber( Bodypart * ) const;

    List<Bodypart> * allBodyparts() const;

    void setRfc822Size( uint );
    uint rfc822Size() const;
    void setInternalDate( uint );
    uint internalDate() const;

    bool hasHeaders() const;
    void setHeadersFetched();
    bool hasAddresses() const;
    void setAddressesFetched();
    bool hasTrivia() const;
    void setTriviaFetched( bool );
    bool hasBodies() const;
    void setBodiesFetched();
    bool hasBytesAndLines() const;
    void setBytesAndLinesFetched();
    bool hasPGPsignedPart() const;
    void setPGPsignedPart( bool );
    
    void setRawSignedMessageBody( const EString & );

    static UString baseSubject( const UString & );

    static EString acceptableBoundary( const EString & );

    void addMessageId( const EString & );

    static Header * parseHeader( uint &, uint, const EString &, Header::Mode );

private:
    void fix8BitHeaderFields();

private:
    class MessageData * d;
    friend class MessageBodyFetcher;
};


#endif
