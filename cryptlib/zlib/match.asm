; match.asm -- Pentium-Pro optimized version of longest_match()
;
; Updated for zlib 1.1.3 and converted to MASM 6.1x
; Copyright (C) 2000 Dan Higdon <dhigdon@acclaim.com>
;                    and Chuck Walbourn <chuckw@beep23.com>
; 
; For conditions of distribution and use, see copyright notice in zlib.h 

; Based on match.S
; Written for zlib 1.1.2
; Copyright (C) 1998 Brian Raiter <breadbox@muppetlabs.com>

.686p
        ASSUME cs:FLAT,ds:FLAT,es:FLAT
        OPTION SCOPED                   ; Enable local labels.

;===========================================================================
; EQUATES
;===========================================================================

MAX_MATCH	    EQU 258
MIN_MATCH	    EQU 3
MIN_LOOKAHEAD	EQU (MAX_MATCH + MIN_MATCH + 1)
MAX_MATCH_8	    EQU ((MAX_MATCH + 7) AND (NOT 7))

;===========================================================================
; STRUCTURES
;===========================================================================

; By using STRUCT and the /Zp directive, this eliminates the brittleness
; of the code relative to compiler packing, assuming the correct packing
; is set for the assembly step as is used by the compiler

DEFLATE_STATE  STRUCT
ds_strm                 dd ?
ds_status               dd ?
ds_pending_buf          dd ?
ds_pending_buf_size     dd ?
ds_pending_out          dd ?
ds_pending              dd ?
ds_noheader             dd ?
ds_data_type            db ?
ds_method               db ?
ds_last_flush           dd ?
ds_w_size               dd ?        ; used
ds_w_bits               dd ?
ds_w_mask               dd ?        ; used
ds_window               dd ?        ; used
ds_window_size          dd ?
ds_prev                 dd ?        ; used
ds_head                 dd ?
ds_ins_h                dd ?
ds_hash_size            dd ?
ds_hash_bits            dd ?
ds_hash_mask            dd ?
ds_hash_shift           dd ?
ds_block_start          dd ?
ds_match_length         dd ?        ; used
ds_prev_match           dd ?        ; used
ds_match_available      dd ?
ds_strstart             dd ?        ; used
ds_match_start          dd ?        ; used
ds_lookahead            dd ?        ; used
ds_prev_length          dd ?        ; used
ds_max_chain_length     dd ?        ; used
ds_max_laxy_match       dd ?
ds_level                dd ?
ds_strategy             dd ?
ds_good_match           dd ?        ; used
ds_nice_match           dd ?        ; used

; Don't need anymore of the struct for match
DEFLATE_STATE  ENDS

;===========================================================================
; CODE 
;===========================================================================
_TEXT  SEGMENT PARA PUBLIC USE32 'CODE'

;---------------------------------------------------------------------------
; match_init
;---------------------------------------------------------------------------
        ALIGN   16
match_init proc    C
        ; no initialization needed
        ret
match_init endp

;---------------------------------------------------------------------------
; uInt longest_match(deflate_state *deflatestate, IPos curmatch)
;---------------------------------------------------------------------------
        ALIGN   16

PUBLIC  _longest_match
_longest_match  PROC

; Since this code uses EBP for a scratch register, the stack frame must
; be manually constructed and referenced relative to the ESP register.

; Stack image
;   Parameters
curmatch        = 60
deflatestate    = 56
retaddr         = 52

;   Saved Registers (actually pushed into place)
ebp_save        = 48
edi_save        = 44
esi_save        = 40
ebx_save        = 36


;   Variables
varsize         = 36           ; Number of bytes (also offset to last saved register)
chainlenwmask   = 32           ; high word: current chain len
                               ; low word: s->wmask
window          = 28           ; local copy of s->window
windowbestlen   = 24           ; s->window + bestlen
scanend         = 20           ; last two bytes of string
scanstart       = 16           ; first two bytes of string
scanalign       = 12           ; dword-misalignment of string
nicematch       = 8            ; a good enough match size
bestlen         = 4            ; size of best match so far
scan            = 0            ; ptr to string wanting match

; Save registers that the compiler may be using
        push    ebp
        push    edi
        push    esi
        push    ebx

; Allocate local variable space
        sub     esp,varsize


; Retrieve the function arguments. ecx will hold cur_match
; throughout the entire function. edx will hold the pointer to the
; deflate_state structure during the function's setup (before
; entering the main loop).						*/

        mov    edx, [esp+deflatestate]
assume  edx:PTR DEFLATE_STATE

        mov    ecx, [esp+curmatch]

; uInt wmask = s->w_mask;
; unsigned chain_length = s->max_chain_length;
; if (s->prev_length >= s->good_match) { 
;     chain_length >>= 2; 
; }

        mov     eax, [edx].ds_prev_length
        mov     ebx, [edx].ds_good_match
        cmp     eax, ebx
        mov     eax, [edx].ds_w_mask
        mov     ebx, [edx].ds_max_chain_length
        jl      SHORT @f    ; LastMatchGood
        shr     ebx, 2
@@:

; chainlen is decremented once beforehand so that the function can
; use the sign flag instead of the zero flag for the exit test.
; It is then shifted into the high word, to make room for the wmask
; value, which it will always accompany.

        dec     ebx
        shl     ebx, 16
        or      ebx, eax
        mov     [esp+chainlenwmask], ebx

; if ((uInt)nice_match > s->lookahead) nice_match = s->lookahead;

        mov     eax, [edx].ds_nice_match
        mov     ebx, [edx].ds_lookahead
        cmp     ebx, eax
        jl      SHORT @f    ; LookaheadLess
        mov     ebx, eax
@@:     mov     [esp+nicematch], ebx

;/* register Bytef *scan = s->window + s->strstart;			*/

        mov     esi, [edx].ds_window
        mov     [esp+window], esi
        mov     ebp, [edx].ds_strstart
        lea     edi, [esi+ebp]
        mov     [esp+scan],edi

;/* Determine how many bytes the scan ptr is off from being		*/
;/* dword-aligned.							*/

        mov     eax, edi
        neg     eax
        and     eax, 3
        mov     [esp+scanalign], eax

;/* IPos limit = s->strstart > (IPos)MAX_DIST(s) ?			*/
;/*     s->strstart - (IPos)MAX_DIST(s) : NIL;				*/

        mov     eax, [edx].ds_w_size
        sub     eax, MIN_LOOKAHEAD
        sub     ebp, eax
        jg      SHORT @f    ; LimitPositive
        xor     ebp, ebp
@@:

;/* int best_len = s->prev_length;					*/

        mov     eax, [edx].ds_prev_length
        mov     [esp+bestlen], eax

;/* Store the sum of s->window + best_len in %esi locally, and in %esi.	*/

        add     esi, eax
        mov     [esp+windowbestlen], esi

;/* register ush scan_start = *(ushf*)scan;				*/
;/* register ush scan_end   = *(ushf*)(scan+best_len-1);			*/
;/* Posf *prev = s->prev;						*/

        movzx   ebx, WORD PTR[edi]
        mov     [esp+scanstart], ebx
        movzx   ebx, WORD PTR[eax+edi-1]
        mov     [esp+scanend], ebx
        mov     edi, [edx].ds_prev

;/* Jump into the main loop.						*/

        mov     edx, [esp+chainlenwmask]
		jmp	    SHORT LoopEntry

;/* do {
; *     match = s->window + cur_match;
; *     if (*(ushf*)(match+best_len-1) != scan_end ||
; *         *(ushf*)match != scan_start) continue;
; *     [...]
; * } while ((cur_match = prev[cur_match & wmask]) > limit
; *          && --chain_length != 0);
; *
; * Here is the inner loop of the function. The function will spend the
; * majority of its time in this loop, and majority of that time will
; * be spent in the first ten instructions.
; *
; * Within this loop:
; * %ebx = scanend
; * %ecx = curmatch
; * %edx = chainlenwmask - i.e., ((chainlen << 16) | wmask)
; * %esi = windowbestlen - i.e., (window + bestlen)
; * %edi = prev
; * %ebp = limit
; */

        ALIGN   16
LookupLoop:
        and     ecx, edx
        movzx   ecx, WORD PTR[edi+ecx*2]
        cmp     ecx, ebp
        jbe     LeaveNow
        sub     edx, 000010000H
        js      LeaveNow

LoopEntry:
    	movzx   eax, WORD PTR[esi+ecx-1]
        cmp     eax, ebx
        jnz     SHORT LookupLoop

        mov     eax, [esp+window]
        movzx   eax, WORD PTR[eax+ecx]
        cmp     eax, [esp+scanstart]
        jnz     SHORT LookupLoop

;/* Store the current value of chainlen.					*/

        mov     [esp+chainlenwmask], edx

;/* Point %edi to the string under scrutiny, and %esi to the string we	*/
;/* are hoping to match it up with. In actuality, %esi and %edi are	*/
;/* both pointed (MAX_MATCH_8 - scanalign) bytes ahead, and %edx is	*/
;/* initialized to -(MAX_MATCH_8 - scanalign).				*/

        mov     esi, [esp+window]
        mov     edi, [esp+scan]
        add     esi, ecx
        mov     eax, [esp+scanalign]
        mov     edx, -MAX_MATCH_8
        lea     edi, [edi+eax+MAX_MATCH_8]
        lea     esi, [esi+eax+MAX_MATCH_8]


;/* Test the strings for equality, 8 bytes at a time. At the end,
; * adjust %edx so that it is offset to the exact byte that mismatched.
; *
; * We already know at this point that the first three bytes of the
; * strings match each other, and they can be safely passed over before
; * starting the compare loop. So what this code does is skip over 0-3
; * bytes, as much as necessary in order to dword-align the %edi
; * pointer. (%esi will still be misaligned three times out of four.)
; *
; * It should be confessed that this loop usually does not represent
; * much of the total running time. Replacing it with a more
; * straightforward "rep cmpsb" would not drastically degrade
; * performance.
; */


LoopCmps:
        mov     eax, DWORD PTR[esi+edx]
        xor     eax, DWORD PTR[edi+edx]
        jnz     SHORT LeaveLoopCmps

        mov     eax, DWORD PTR[esi+edx+4]
        xor     eax, DWORD PTR[edi+edx+4]
        jnz     SHORT LeaveLoopCmps4

        add     edx, 8
        jnz     SHORT LoopCmps
        jmp     LenMaximum
        ALIGN   16

LeaveLoopCmps4:
        add     edx, 4

LeaveLoopCmps:
        test    eax, 00000FFFFH
        jnz     SHORT LenLower

        add     edx, 2
        shr     eax, 16

LenLower:
        sub     al, 1
        adc     edx, 0

;/* Calculate the length of the match. If it is longer than MAX_MATCH,	*/
;/* then automatically accept it as the best possible match and leave.	*/

        lea     eax, [edi+edx]
        mov     edi, [esp+scan]
        sub     eax, edi
        cmp     eax, MAX_MATCH
        jge     SHORT LenMaximum


;/* If the length of the match is not longer than the best match we	*/
;/* have so far, then forget it and return to the lookup loop.		*/

        mov     edx, [esp+deflatestate]
        mov     ebx, [esp+bestlen]
        cmp     eax, ebx
        jg      SHORT LongerMatch
        mov     esi, [esp+windowbestlen]
        mov     edi, [edx].ds_prev
        mov     ebx, [esp+scanend]
        mov     edx, [esp+chainlenwmask]
        jmp     LookupLoop
        ALIGN   16

;/*         s->match_start = cur_match;					*/
;/*         best_len = len;						*/
;/*         if (len >= nice_match) break;				*/
;/*         scan_end = *(ushf*)(scan+best_len-1);			*/

LongerMatch:
        mov     ebx, [esp+nicematch]
        mov     [esp+bestlen], eax
        mov     [edx].ds_match_start, ecx
        cmp     eax, ebx
        jge     SHORT LeaveNow
        mov     esi, [esp+window]
        add     esi, eax
        mov     [esp+windowbestlen], esi
        movzx   ebx, WORD PTR[edi+eax-1]
        mov     edi, [edx].ds_prev
        mov     [esp+scanend], ebx
        mov     edx, [esp+chainlenwmask]
        jmp     LookupLoop
        ALIGN   16

;/* Accept the current string, with the maximum possible length.		*/

LenMaximum:
        mov     edx, [esp+deflatestate]
        mov     DWORD PTR[esp+bestlen], MAX_MATCH
        mov     [edx].ds_match_start, ecx

;/* if ((uInt)best_len <= s->lookahead) return (uInt)best_len;		*/
;/* return s->lookahead;							*/

LeaveNow:
        mov     edx, [esp+deflatestate]
        mov     ebx, [esp+bestlen]
        mov     eax, [edx].ds_lookahead
        cmp     ebx, eax
        jg      SHORT @f    ; LookaheadRet
        mov     eax, ebx
@@:

; Restore the stack and return from whence we came.

        add     esp, varsize
        pop     ebx
        pop     esi
        pop     edi
        pop     ebp
        ret

_longest_match endp

_text   ends
        end

; eof - match.asm
