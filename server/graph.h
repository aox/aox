// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef GRAPH_H
#define GRAPH_H

#include "string.h"
#include "connection.h"


class GraphableNumber
    : public Garbage
{
public:
    GraphableNumber( const String & );

    void setValue( uint );
    uint maximumSince( uint ) const;
    uint minimumSince( uint ) const;
    uint averageSince( uint ) const;
    uint lastValue() const;

    String name() const;
    uint oldestTime() const;
    uint youngestTime() const;
    uint value( uint );

private:
    class GraphableNumberData * d;
    void clearOldHistory( uint );
};


class GraphableCounter
    : public GraphableNumber
{
public:
    GraphableCounter( const String & );

    void tick();
};


class GraphableDataSet
    : public GraphableNumber
{
public:
    GraphableDataSet( const String & );

    void addNumber( uint );

private:
    class GraphableDataSetData * d;
};


class GraphDumper
    : public Connection
{
public:
    GraphDumper( int );

    void react( Event );
};


#endif
