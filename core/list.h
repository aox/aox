#ifndef LIST_H
#define LIST_H

#include "global.h"
#include "string.h"


template< class T >
class List {
public:
    List() { head = tail = 0; }
    ~List() {}


    class Node {
    public:
        Node( T *d ) {
            prev = next = 0;
            data = d;
        }

        Node *prev, *next;
        T *data;
    };


    bool isEmpty() const
    {
        return head == 0;
    }

    unsigned int count() const
    {
        unsigned int n = 0;
        Node *cur = head;

        while ( cur ) {
            cur = cur->next;
            n++;
        }

        return n;
    }

    void clear()
    {
        Node *cur = head;
        while ( cur ) {
            Node *n = cur->next;
            delete cur;
            cur = n;
        }
        head = tail = 0;
    }


    class Iterator {
    public:
        Iterator()                   { cur = 0; }
        Iterator( Node *n )          { cur = n; }

        Node *node() const           { return cur; }
        operator bool()              { return cur != 0; }
        operator T *()               { return cur ? cur->data : 0; }
        T *operator ->()             { ok(); return cur->data; }
        Iterator &operator ++()      { ok(); return next(); }
        Iterator &operator --()      { ok(); return prev(); }
        Iterator &operator ++( int ) {
            ok();
            Node *p = cur; cur = cur->next;
            return newRef(p);
        }

        Iterator &operator --( int ) {
            ok();
            Node *p = cur; cur = cur->prev;
            return newRef(p);
        }

        T &operator *() {
            ok();
            if ( !cur->data )
                throw Range;
            return *(cur->data);
        }

        bool operator ==( const Iterator &x ) { return cur == x.cur; }
        bool operator !=( const Iterator &x ) { return cur != x.cur; }

        static Iterator &newRef( Node *n ) {
            return *( new Iterator(n) );
        }

    private:
        Iterator &next() { cur = cur->next; return *this; }
        Iterator &prev() { cur = cur->prev; return *this; }

        void ok() {
            if ( !cur )
                throw Range;
        }

        Node *cur;
    };


    Iterator &first() const { return Iterator::newRef( head ); }
    Iterator &last()  const { return Iterator::newRef( tail ); }
    Iterator &end()   const { return Iterator::newRef( 0 );    }


    T *take( Iterator &i )
    {
        Node *cur = i.node();

        if ( !cur )
            return 0;
        if ( cur->next )
            cur->next->prev = cur->prev;
        if ( cur->prev )
            cur->prev->next = cur->next;

        if ( cur == head )
            head = cur->next;
        if ( cur == tail )
            tail = cur->prev;

        i++;

        T *d = cur->data;
        delete cur;
        return d;
    }


    T *pop()
    {
        return take( last() );
    }

    T *shift()
    {
        return take( first() );
    }


    Iterator &insert( const Iterator &i, T *d )
    {
        Node *n = new Node( d );
        Node *cur = i.node();

        if ( !head && !tail ) {
            head = tail = n;
        }
        else if ( !cur ) {
            tail->next = n;
            n->prev = tail;
            tail = n;
        }
        else if ( head == cur ) {
            head->prev = n;
            n->next = head;
            head = n;
        }
        else {
            n->next = cur;
            n->prev = cur->prev;
            cur->prev->next = n;
            cur->prev = n;
        }

        return Iterator::newRef( n );
    }

    void append( T *d )
    {
        insert( end(), d );
    }

    void prepend( T *d )
    {
        insert( first(), d );
    }


    Iterator &find( const T *d )
    {
        Node *cur = head;

        while ( cur && cur->data != d )
            cur = cur->next;
        return Iterator::newRef( cur );
    }

    Iterator &find( const String &s )
    {
        Node *cur = head;

        while ( cur && *cur->data != s )
            cur = cur->next;
        return Iterator::newRef( cur );
    }


    String string() const
    {
        String r;
        Iterator it = first();

        while ( it ) {
            const String &s = *it++;
            r.append( "(" + s + ")" );
        }

        return r;
    }

private:
    Node *head, *tail;

    // Some operators are disabled because of unpredictable behaviour.
    // (Deep copy? Does order matter for equality?)
    List< T > &operator =( const List< T > & ) { return *this; }
    bool operator ==( const List< T > & ) const { return false; }
    bool operator !=( const List< T > & ) const { return false; }
};

template< class T >
class SortedList
    : public List< T >
{
public:
    typedef typename List< T >::Iterator Iterator;

    Iterator &insert( T *d )
    {
        Iterator it = first();
        while ( it && *it <= *d )
            it++;

        return List< T >::insert( it, d );
    }
};

#endif
