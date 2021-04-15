package srmgo

/*
#include "srm.h"
*/
import "C"

import (
	"errors"
	"strconv"
	"sync"
	"unicode/utf8"
	"unsafe"
)

// Srmgo is the representation of a compiled regular expression.
// A srmgo is safe for concurrent use by multiple goroutines,
// except for configuration methods, such as Longest.
type Srmgo struct {
	expr            string // as passed to Compile
	prog            unsafe.Pointer
	Flag            uint32
	MatchBuffer     []uint32
	MatchBufferSize int

	// prog           *syntax.Prog // compiled program
	// onepass        *onePassProg // onepass program or nil
	numSubexp int
	// maxBitStateLen int
	subexpNames []string
	prefix      string // required prefix in unanchored matches
	prefixBytes []byte // prefix, as a []byte
	prefixRune  rune   // first rune in prefix
	// prefixEnd      uint32         // pc for last rune in prefix
	mpool int // pool for machines
	// matchcap       int            // size of recorded match lengths
	prefixComplete bool // prefix is the entire srmgo
	// cond           syntax.EmptyOp // empty-width conditions required at start of match
	minInputLen int // minimum length of the input in bytes

	// This field can be modified by the Longest method,
	// but it is otherwise read-only.
	longest bool // whether srmgo prefers leftmost-longest match

}

// String returns the source text used to compile the regular expression.
func (re *Srmgo) String() string {
	return re.expr
}

// Copy returns a new srmgo object copied from re.
// Calling Longest on one copy does not affect another.
//
// Deprecated: In earlier releases, when using a srmgo in multiple goroutines,
// giving each goroutine its own copy helped to avoid lock contention.
// As of Go 1.12, using Copy is no longer necessary to avoid lock contention.
// Copy may still be appropriate if the reason for its use is to make
// two copies with different Longest settings.
func (re *Srmgo) Copy() *Srmgo {
	re2 := *re
	return &re2
}

// Compile parses a regular expression and returns, if successful,
// a srmgo object that can be used to match against text.
//
// When matching against text, the srmgo returns a match that
// begins as early as possible in the input (leftmost), and among those
// it chooses the one that a backtracking search would have found first.
// This so-called leftmost-first matching is the same semantics
// that Perl, Python, and other implementations use, although this
// package implements it without the expense of backtracking.
// For POSIX leftmost-longest matching, see CompilePOSIX.
func Compile(expr string) (*Srmgo, error) {
	return compile(expr, 0)
}

// CompilePOSIX is like Compile but restricts the regular expression
// to POSIX ERE (egrep) syntax and changes the match semantics to
// leftmost-longest.
//
// That is, when matching against text, the srmgo returns a match that
// begins as early as possible in the input (leftmost), and among those
// it chooses a match that is as long as possible.
// This so-called leftmost-longest matching is the same semantics
// that early regular expression implementations used and that POSIX
// specifies.
//
// However, there can be multiple leftmost-longest matches, with different
// submatch choices, and here this package diverges from POSIX.
// Among the possible leftmost-longest matches, this package chooses
// the one that a backtracking search would have found first, while POSIX
// specifies that the match be chosen to maximize the length of the first
// subexpression, then the second, and so on from left to right.
// The POSIX rule is computationally prohibitive and not even well-defined.
// See https://swtch.com/~rsc/srmgo/srmgo2.html#posix for details.
// func CompilePOSIX(expr string) (*Srmgo, error) {
// 	return compile(expr, 0)
// }

// Longest makes future searches prefer the leftmost-longest match.
// That is, when matching against text, the srmgo returns a match that
// begins as early as possible in the input (leftmost), and among those
// it chooses a match that is as long as possible.
// This method modifies the srmgo and may not be called concurrently
// with any other methods.
func (re *Srmgo) Longest() {
	re.longest = true
}

func compile(expr string, nFlag uint32) (*Srmgo, error) {

	mc := make([]byte, 255)
	for i := range mc {
		mc[i] = byte(i + 1)

	}

	matchCharSet := (*C.char)(unsafe.Pointer(&mc[0]))

	prog := C.SRM_compile(C.CString(expr), C.int(1<<31|nFlag), matchCharSet, 255)

	if *(*int)(prog) == 0 {
		return nil, errors.New("compile err")
	}

	srmgo := &Srmgo{
		expr:        expr,
		prog:        prog,
		Flag:        nFlag,
		MatchBuffer: make([]uint32, 1024),
	}

	return srmgo, nil
}

// //Free srmgo free
// func (re *Srmgo) Free() {
// 	C.free(unsafe.Pointer(re.prog))
// }

// Pools of *machine for use during (*srmgo).doExecute,
// split up by the size of the execution queues.
// matchPool[i] machines have queue size matchSize[i].
// On a 64-bit system each queue entry is 16 bytes,
// so matchPool[0] has 16*2*128 = 4kB queues, etc.
// The final matchPool is a catch-all for very large queues.
var (
	matchSize = [...]int{128, 512, 2048, 16384, 0}
	matchPool [len(matchSize)]sync.Pool
)

// MustCompile is like Compile but panics if the expression cannot be parsed.
// It simplifies safe initialization of global variables holding compiled regular
// expressions.
func MustCompile(str string) *Srmgo {
	srmgo, err := Compile(str)
	if err != nil {
		panic(`srmgo: Compile(` + quote(str) + `): ` + err.Error())
	}
	return srmgo

}

//MustCompileWithFlag  must Compile
func MustCompileWithFlag(str string, nFlag uint32) *Srmgo {
	srmgo, err := CompileWithFlag(str, nFlag)
	if err != nil {
		panic(`srmgo: Compile(` + quote(str) + `): ` + err.Error())
	}
	return srmgo
}

//CompileWithFlag with flag
func CompileWithFlag(str string, nFlag uint32) (*Srmgo, error) {
	return compile(str, nFlag)

}

// MustCompilePOSIX is like CompilePOSIX but panics if the expression cannot be parsed.
// It simplifies safe initialization of global variables holding compiled regular
// expressions.
// func MustCompilePOSIX(str string) *Srmgo {
// 	srmgo, err := CompilePOSIX(str)
// 	if err != nil {
// 		panic(`srmgo: CompilePOSIX(` + quote(str) + `): ` + err.Error())
// 	}
// 	return srmgo
// }

func quote(s string) string {
	if strconv.CanBackquote(s) {
		return "`" + s + "`"
	}
	return strconv.Quote(s)
}

// NumSubexp returns the number of parenthesized subexpressions in this srmgo.
func (re *Srmgo) NumSubexp() int {
	return re.numSubexp
}

// Free memory in this srmgo.
func (re *Srmgo) Free() {
	C.SRM_free(re.prog)
	// C.free(re.prog)
}

//C.SRM_free(prog)

// SubexpNames returns the names of the parenthesized subexpressions
// in this srmgo. The name for the first sub-expression is names[1],
// so that if m is a match slice, the name for m[i] is SubexpNames()[i].
// Since the srmgo as a whole cannot be named, names[0] is always
// the empty string. The slice should not be modified.
func (re *Srmgo) SubexpNames() []string {
	return re.subexpNames
}

const endOfText rune = -1

// input abstracts different representations of the input text. It provides
// one-character lookahead.
type input interface {
	step(pos int) (r rune, width int) // advance one rune
	canCheckPrefix() bool             // can we look ahead without losing info?
	hasPrefix(re *Srmgo) bool
	index(re *Srmgo, pos int) int
	//	context(pos int) lazyFlag
}

// LiteralPrefix returns a literal string that must begin any match
// of the regular expression re. It returns the boolean true if the
// literal string comprises the entire regular expression.
func (re *Srmgo) LiteralPrefix() (prefix string, complete bool) {
	return re.prefix, re.prefixComplete
}

// MatchString reports whether the string s
// contains any match of the regular expression re.
func (re *Srmgo) MatchString(s string) bool {

	i := C.SRM_search(re.prog, C.CString(s))

	if i == -1 {
		return false
	}

	//	fmt.Println("matchstring i is ", i)

	return true
}

// Match reports whether the byte slice b
// contains any match of the regular expression re.
func (re *Srmgo) Match(b []byte) bool {
	i := C.SRM_search(re.prog, C.CString(string(b)))
	if i == -1 {
		return false
	}
	return true
}

// doMatch reports whether either r, b or s match the regexp.
// func (re *srmgo) doMatch(r io.RuneReader, b []byte, s string) bool {
// 	return re.doExecute(r, b, s, 0, 0, nil) != nil
// }

// doExecute finds the leftmost match in the input, appends the position
// of its subexpressions to dstCap and returns dstCap.
//
// nil is returned if no matches are found and non-nil if matches are found.

// MatchReader reports whether the text returned by the RuneReader
// contains any match of the regular expression pattern.
// More complicated queries need to use Compile and the full srmgo interface.

// MatchString reports whether the string s
// contains any match of the regular expression pattern.
// More complicated queries need to use Compile and the full srmgo interface.
func MatchString(pattern string, s string) (matched bool, err error) {
	re, err := Compile(pattern)
	if err != nil {
		return false, err
	}
	matched = re.MatchString(s)
	re.Free()
	return matched, nil
}

// Match reports whether the byte slice b
// contains any match of the regular expression pattern.
// More complicated queries need to use Compile and the full srmgo interface.
func Match(pattern string, b []byte) (matched bool, err error) {
	re, err := Compile(pattern)
	if err != nil {
		return false, err
	}
	matched = re.Match(b)
	re.Free()
	return matched, nil
}

// Bitmap used by func special to check whether a character needs to be escaped.
var specialBytes [16]byte

// special reports whether byte b needs to be escaped by QuoteMeta.
func special(b byte) bool {
	return b < utf8.RuneSelf && specialBytes[b%16]&(1<<(b/16)) != 0
}

func init() {
	for _, b := range []byte(`\.+*?()|[]{}^$`) {
		specialBytes[b%16] |= 1 << (b / 16)
	}
}

// QuoteMeta returns a string that escapes all regular expression metacharacters
// inside the argument text; the returned string is a regular expression matching
// the literal text.
func QuoteMeta(s string) string {
	// A byte loop is correct because all metacharacters are ASCII.
	var i int
	for i = 0; i < len(s); i++ {
		if special(s[i]) {
			break
		}
	}
	// No meta characters found, so return original string.
	if i >= len(s) {
		return s
	}

	b := make([]byte, 2*len(s)-i)
	copy(b, s[:i])
	j := i
	for ; i < len(s); i++ {
		if special(s[i]) {
			b[j] = '\\'
			j++
		}
		b[j] = s[i]
		j++
	}
	return string(b[:j])
}

// FindIndex returns a two-element slice of integers defining the location of
// the leftmost match in b of the regular expression. The match itself is at
// b[loc[0]:loc[1]].
// A return value of nil indicates no match.
func (re *Srmgo) FindIndex(b []byte) (loc []uint32) {

	mb := make([]uint32, 10)

	pMatchBuffer := (*C.uint)(unsafe.Pointer(&mb[0]))

	C.SRM_match(re.prog, C.CString(string(b)), pMatchBuffer, C.int(len(mb)))

	//	fmt.Println("FindIndexmb:", mb, "\ni:", i, "buffer:", pMatchBuffer)

	return mb

}

// FindStringIndex returns a two-element slice of integers defining the
// location of the leftmost match in s of the regular expression. The match
// itself is at s[loc[0]:loc[1]].
// A return value of nil indicates no match.
func (re *Srmgo) FindStringIndex(s string, macthbuf []uint32) (loc []uint32) {

	//loc = make([]uint32, 1000)

	pMatchBuffer := (*C.uint)(unsafe.Pointer(&macthbuf[0]))
	cs := C.CString(s)
	size := int(C.SRM_match(re.prog, cs, pMatchBuffer, C.int(len(macthbuf))))
	//C.CString 需要手动释放
	C.free(unsafe.Pointer(cs))
	// fmt.Println(size)
	// fmt.Println(int(size), re.MatchBuffer)
	// defer C.free(unsafe.Pointer(pMatchBuffer))
	if size > 0 {
		loc = macthbuf[:size]
	}
	// re.Free()
	return

	//fmt.Println("FindStringIndex mb:", loc, "\ni:", i, "\nbuffer:", pMatchBuffer)

	//	return loc
}

func (re *Srmgo) FindStringExt(s string, macthbuf, indexbuf []uint32) (loc, array []uint32) {

	//loc = make([]uint32, 1000)

	pMatchBuffer := (*C.uint)(unsafe.Pointer(&macthbuf[0]))
	pArrayBuffer := (*C.uint)(unsafe.Pointer(&indexbuf[0]))
	cs := C.CString(s)
	size := int(C.SRM_match_ex(re.prog, cs, pMatchBuffer, pArrayBuffer, C.int(len(macthbuf))))
	//C.CString 需要手动释放
	C.free(unsafe.Pointer(cs))
	// fmt.Println(size)
	// fmt.Println(int(size), re.MatchBuffer)
	// defer C.free(unsafe.Pointer(pMatchBuffer))
	if size > 0 {
		loc = macthbuf[:size]
		array = indexbuf[:size]
		// fmt.Println(indexbuf[:size])
	}
	// re.Free()
	return

	//fmt.Println("FindStringIndex mb:", loc, "\ni:", i, "\nbuffer:", pMatchBuffer)

	//	return loc
}
