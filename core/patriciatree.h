// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef PATRICIATREE_H
#define PATRICIATREE_H

#include "global.h"
#include "allocator.h"


template< class T >
class PatriciaTree
    : public Garbage
{
public:
    PatriciaTree(): root( 0 ) { }
    virtual ~PatriciaTree() { clear(); }

    class Node
        : public Garbage
    {
    public:
        Node() : zero( 0 ), one( 0 ),
                 parent( 0 ),
                 data( 0 ), length( 0 ) {
            setFirstNonPointer( &length );
        }

        uint count() {
            uint c = 0;
            if ( data )
                c = 1;
            if ( zero )
                c += zero->count();
            if ( one )
                c += one->count();
            return c;
        }

        void * operator new( size_t ownSize, uint extra ) {
            return Allocator::alloc( ownSize + extra );
        }

        void clear() {
            if ( zero )
                zero->clear();
            if ( one )
                one->clear();
            zero = 0;
            one = 0;
            parent = 0;
        }

    private:
        friend class PatriciaTree;
        friend class PatriciaTree::Iterator;
        Node * zero;
        Node * one;
        Node * parent;
        T * data;
        uint length;
        char key[1];
    };

    T * find( const char * k, uint l ) const {
        Node * n = locate( k, l );
        if ( n )
            return n->data;
        return 0;
    }

    T * remove( Node * n ) {
        if ( !n )
            return 0;
        T * r = n->data;

        if ( n->zero || n->one ) {
            // this is an internal node, so we have to drop the
            // data, then do no more.
            n->data = 0;
            return r;
        }

        if ( !n->parent ) {
            // this is the root
            root = 0;
            free( n );
        }
        else if ( n->parent->data ) {
            // the parent has to lose this child, but has data, so
            // it has to stay
            if ( n->parent->zero == n )
                n->parent->zero = 0;
            else
                n->parent->one = 0;
            free( n );
        }
        else {
            // the other child can be promoted to the parent's slot.
            Node * p = n->parent;
            Node * c = p->zero;
            if ( c == n )
                c = p->one;
            if ( c )
                c->parent = p->parent;
            if ( !p->parent )
                root = c;
            else if ( p->parent->one == p )
                p->parent->one = c;
            else
                p->parent->zero = c;
            free( p );
            free( n );
        }
        return r;
    }

    T * remove( const char * k, uint l ) {
        return remove( locate( k, l ) );
    }

    void insert( const char * k, uint l, T * t ) {
        Node * n = root;
        bool d = false;
        uint b = 0;
        while ( n && !d ) {
            // check entire bytes until we run out of something
            while ( !d &&
                    b / 8 < l / 8 &&
                    b / 8 < n->length / 8 ) {
                if ( k[b/8] == n->key[b/8] )
                    b = ( b | 7 ) + 1;
                else
                    d = true;
            }
            // if no entire byte differed, see if the last bits of n
            // differ from k
            if ( !d && b < n->length && n->length <= l ) {
                uint mask = ( 0xff00 >> (n->length%8) ) & 0xff;
                if ( ( k[b/8] & mask ) == ( n->key[b/8] & mask ) )
                    b = n->length;
                else
                    d = true;
            }
            // if we found a difference, then set b to the first
            // differing bit
            if ( d && b < n->length && b < l ) {
                uint mask = 128 >> ( b % 8 );
                while ( b < n->length && b < l &&
                        ( k[b/8] & mask ) == ( n->key[b/8] & mask ) ) {
                    b++;
                    mask >>= 1;
                    if ( !mask )
                        mask = 128;
                }
            }
            // if the first differing bit is at the end of this node,
            // then we need to go to the right child
            if ( b == n->length ) {
                if ( b == l ) {
                    // no, not to the child, n IS the right node
                    n->data = t;
                    return;
                }
                d = false;
                Node * c = 0;
                if ( k[b / 8] & ( 128 >> ( b % 8 ) ) )
                    c = n->one;
                else
                    c = n->zero;
                if ( c )
                    n = c;
                else
                    d = true;
            }
            if ( b == l && l < n->length )
                d = true;
        }

        uint kl = (l+7) / 8;
        Node * x = node( kl );
        x->length = l;
        x->data = t;
        uint i = 0;
        while ( i < kl ) {
            x->key[i] = k[i];
            i++;
        }

        if ( !n ) {
            // the tree is empty; x is the new root
            root = x;
        }
        else if ( b == n->length ) {
            // n's key is a prefix of k, so x must be a child of n
            x->parent = n;
            if ( k[b / 8] & ( 128 >> ( b % 8 ) ) )
                n->one = x;
            else
                n->zero = x;
        }
        else if ( b == l ) {
            // k is a prefix of n's key, so n must be a child of x
            x->parent = n->parent;
            n->parent = x;
            if ( !x->parent )
                root = x;
            else if ( x->parent->one == n )
                x->parent->one = x;
            else
                x->parent->zero = x;
            if ( n->key[b / 8] & ( 128 >> ( b % 8 ) ) )
                x->one = n;
            else
                x->zero = n;
        }
        else {
            // n's key and k differ, so we make a new intermediate node
            kl = (b+7) / 8;
            Node * p = node( kl );
            x->parent = p;
            p->parent = n->parent;
            n->parent = p;
            if ( !p->parent )
                root = p;
            else if ( p->parent->one == n )
                p->parent->one = p;
            else
                p->parent->zero = p;
            if ( k[b / 8] & ( 128 >> ( b % 8 ) ) ) {
                p->zero = n;
                p->one = x;
            }
            else {
                p->zero = x;
                p->one = n;
            }

            p->length = b;
            i = 0;
            while ( i < kl ) {
                p->key[i] = k[i];
                i++;
            }
        }
    }

    bool isEmpty() {
        if ( !root )
            return true;
        // is it possible for a tree to contain no data nodes? no?
        return false;
    }

    uint count() const {
        if ( !root )
            return 0;
        return root->count();
    }

    void clear() {
        if ( !root )
            return;
        root->clear();
        root = 0;
    }

    class Iterator
        : public Garbage
    {
    public:
        Iterator()                   { cur = 0; }
        Iterator( Node *n )          { cur = n; }
        Iterator( PatriciaTree<T> * t ) {
            if ( t )
                cur = t->firstNode();
            else
                cur = 0;
        }
        Iterator( const PatriciaTree<T> &t ) {
            cur = t.firstNode();
        }

        operator bool() { return cur && cur->data ? true : false; }
        operator T *() { return cur ? cur->data : 0; }
        T *operator ->() { ok(); return cur->data; }
        Iterator &operator ++() { ok(); return next(); }
        Iterator &operator --() { ok(); return prev(); }
        Iterator &operator ++( int ) {
            ok();
            Node * p = cur; cur = next();
            return newRef(p);
        }

        Iterator &operator --( int ) {
            ok();
            Node *p = cur; cur = prev();
            return newRef(p);
        }


        T &operator *() {
            ok();
            if ( !cur->data )
                die( Invariant );
            return *(cur->data);
        }

        bool operator ==( const Iterator &x ) { return cur == x.cur; }
        bool operator !=( const Iterator &x ) { return cur != x.cur; }

        static Iterator &newRef( Node *n ) {
            return *( new Iterator(n) );
        }

    private:
        Iterator &next() {
            do {
                if ( cur->one ) {
                    cur = cur->one;
                    while ( cur->zero )
                        cur = cur->zero;
                }
                else if ( cur->parent ) {
                    while ( cur->parent && cur->parent->one == cur )
                        cur = cur->parent;
                    if ( cur->parent )
                        cur = cur->parent;
                    else
                        cur = 0;
                }
                else {
                    cur = 0;
                }
            } while ( cur && !cur->data );
            return *this;
        }
        Iterator &prev() {
            do {
                if ( cur->zero ) {
                    cur = cur->zero;
                    while ( cur->one )
                        cur = cur->one;
                }
                else if ( cur->parent ) {
                    while ( cur->parent && cur->parent->zero == cur )
                        cur = cur->parent;
                    if ( cur->parent )
                        cur = cur->parent;
                    else
                        cur = 0;
                }
                else {
                    cur = 0;
                }
            } while ( cur && !cur->data );
            return *this;
        }

        void ok() {
            if ( !cur )
                die( Invariant );
        }

        Node *cur;
    };

    T * remove( Iterator & i ) {
        return remove( i.cur );
    }

    T * first() {
        Node * n = firstNode();
        if ( n )
            return n->data;
        return 0;
    }

    T * last() {
        Node * n = lastNode();
        if ( n )
            return n->data;
        return 0;
    }

private:
    virtual Node * node( uint x ) {
        Node * n = new ( x ) Node;
        return n;
    }
    virtual void free( Node * n ) {
        Allocator::dealloc( n );
    }

    Node * best( const char * k, uint l ) const {
        Node * n = root;
        Node * p = n;
        while ( n && n->length < l ) {
            p = n;
            if ( k[n->length / 8] & ( 128 >> ( n->length % 8 ) ) )
                n = n->one;
            else
                n = n->zero;
        }
        if ( n )
            return n;
        return p;
    }

    Node * ifMatch( Node * n, const char * k, uint l ) const {
        if ( !n )
            return 0;
        if ( n->length != l )
            return 0;
        uint i = 0;
        while ( i < l / 8 ) {
            if ( n->key[i] != k[i] )
                return 0;
            i++;
        }
        return n;
    }

    Node * locate( const char * k, uint l ) const {
        return ifMatch( best( k, l ), k, l );
    }

    Node * firstNode() const {
        Node * n = root;
        while ( n && n->zero )
            n = n->zero;
        return n;
    }

    Node * lastNode() const {
        Node * n = root;
        while ( n && n->one )
            n = n->one;
        return n;
    }

private:
    Node * root;
};


#endif
