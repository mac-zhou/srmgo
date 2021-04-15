
#ifndef SRM_SETFLAG_FLAG
#define SRM_NOCASEFOLDING_FLAG (1 << 0) //大小写敏感
#define SRM_ILLEGAL_CHAR_JUMP (1 << 1)	//非字符集中的字符跳过继续匹配，否则则为从下个字符开始重新匹配
#define SRM_USEDEFAULT_FLAG (1 << 30)	//使用系统缺省的flag
#define SRM_SETFLAG_FLAG (1 << 31)		//设置了此位，其它位才可以设置,没有设置此位,flag设置无效,使用系统现有的flag
#endif

//if support to show the error info
//#define SRM_ERROR_INFO
//if support the debug info print
//#define SRM_DEBUG_INFO
//if support the debug info of match keyword in SRM_match
//#define SRM_DEBUG_MATCH_KEY_INFO
//if support to show the memalloc stat. info
//#define SRM_DEBUG_SHOW_MEMALLOC_INFO
//if support to show the all keywords these are parsed from regex
//#define SRM_DEBUG_SHOW_ALLKEYWORDS_INFO

//is support to compile into a linux kernel module
//#define SRM_LINUX_KERNEL
//if support the spinlock for the gloabl stat. info
//#define SRM_SPIN_LOCK
//if support the inline
//#define SRM_SUPPORT_INLINE
//if support the emulation of the memalloc err
//#define SRM_MEMALLOCERR_TEST

#ifndef PHD_VERSION
#ifdef SRM_LINUX_KERNEL
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#else
#include <stdio.h>
#include <memory.h>
#if defined(__APPLE__) && (defined(__GNUC__) || defined(__xlC__) || defined(__xlc__))
#include <stdlib.h>
#else
#include <malloc.h>
#endif
#include <string.h>
#endif
#endif

#ifndef SRM_DEBUG_SHOW_MEMALLOC_INFO
#ifdef SRM_LINUX_KERNEL
#define SRM_MALLOC(x) kmalloc((x), GFP_KERNEL)
#define SRM_FREE(x) kfree(x)
#else
#define SRM_MALLOC(x) malloc(x)
#define SRM_FREE(x) free(x)
#endif
#endif

#ifdef SRM_LINUX_KERNEL
#define SRM_PRINT printk
#else
#define SRM_PRINT printf
#endif

#ifndef NULL
#define NULL (void *)0
#endif

#ifdef SRM_SUPPORT_INLINE
#ifdef WIN32
#define INLINE __inline
#else
#define INLINE inline
#endif
#else
#define INLINE
#endif

#define MAX_CHAR 256
#define MAX_KEYWORDSIZE 4000
#define MIN_NEXTNODESLEN 2
#define MIN_STRBUFLEN 16

#define SRM_SYSDEFAULT_FLAG (SRM_NOCASEFOLDING_FLAG | SRM_ILLEGAL_CHAR_JUMP)

//error code
#define SRM_COMPILE_NOERROR 0x00
#define SRM_COMPILE_MEM_ERROR 0x101
#define SRM_COMPILE_BRACKETDISMATCH_ERROR 0x102
#define SRM_COMPILE_SQUAREBRACKETDISMATCH_ERROR 0x103
#define SRM_COMPILE_ANGLEBRACKETDISMATCH_ERROR 0x104
#define SRM_COMPILE_KEYWORDVALUE_ERROR 0x106
#define SRM_COMPILE_REFCOUNT_ERROR 0x107
#define SRM_COMPILE_SOLONGKEYWORD_ERROR 0x108

//warning code
#define SRM_COMPILE_NOWARNING 0x00
#define SRM_COMPILE_ILLEGAL_CHAR_WARNING 0x201
#define SRM_COMPILE_SYNTAX_WARNING 0x202

//node flag
#define SRM_NODE_END (1 << 0)
#define SRM_BEGINMATCH (1 << 1)
#define SRM_ENDMATCH (1 << 2)
#define SRM_NOTSET (1 << 15)

//keyword stat flag
#define SRM_BEGINMATCH_STATFLAG (1 << 0)
#define SRM_ENDMATCH_STATFLAG (1 << 1)
#define SRM_OTHERMATCH_STATFLAG (1 << 2)

//some defines
#define SRM_GET_NEXTNODESGOODLEN(n) (((n) / MIN_NEXTNODESLEN + 1) * MIN_NEXTNODESLEN)
#define SRM_GET_STRBUFGOODLEN(n) (((n) / MIN_STRBUFLEN + 1) * MIN_STRBUFLEN)
#define SRM_GET_NEXTNODEIDX(pNow, idx) ((pNow)->m_pCharToNextNodesIdxMap[(idx)])
#define SRM_GET_NEXTNODE(pNow, idx) ((pNow)->m_ppNextNodes[SRM_GET_NEXTNODEIDX((pNow), (idx))])
#define SRM_CHARTOIDX(h, c) ((h)->m_CharToIdxMap[(unsigned char)(c)] == 0 ? -1 : (h)->m_CharToIdxMap[(unsigned char)(c)] - 1)
#define SRM_IDXTOCHAR(h, i) ((h)->m_IdxToCharMap[(i)])
#define SRM_SETERROR(h, c)                                        \
	if ((h)->m_iErrorCode == SRM_COMPILE_NOERROR)                 \
	{                                                             \
		(h)->m_iErrorPos = (int)((h)->m_pToken - (h)->m_pNowStr); \
		(h)->m_iErrorCode = (c);                                  \
		(h)->m_iErrorLine = __LINE__;                             \
	}
#define SRM_SETWARNING(h, c)                                        \
	if ((h)->m_iWarningCode == SRM_COMPILE_NOWARNING)               \
	{                                                               \
		(h)->m_iWarningPos = (int)((h)->m_pToken - (h)->m_pNowStr); \
		(h)->m_iWarningCode = (c);                                  \
		(h)->m_iWarningLine = __LINE__;                             \
	}

typedef struct SRM_keyword_t_dummy
{
	char *m_pStr;
	int m_iStrLen;
	int m_iStrBufLen;
	unsigned int m_uiValue;
	struct SRM_keyword_t_dummy *m_pNext;
} SRM_keyword_t;

typedef struct SRM_keyword_plink_dummy
{
	SRM_keyword_t *m_pKeyWord;
	unsigned int m_uiFlag;
	struct SRM_keyword_plink_dummy *m_pNext;
} SRM_keyword_plink;

typedef struct SRM_node_t_dummy
{
	unsigned int m_uiRefCount;
	unsigned int m_uiFlag;
	SRM_keyword_plink *m_pMatchKeyWordLink;
	unsigned short m_usNextNodesSize;
	unsigned short m_usNextNodesUsedNum;
	unsigned char *m_pCharToNextNodesIdxMap;
	struct SRM_node_t_dummy **m_ppNextNodes;
} SRM_node_t;

typedef struct SRM_node_plink_dummy
{
	SRM_node_t *m_pNode;
	struct SRM_node_plink_dummy *m_pNext;
} SRM_node_plink;

typedef struct SRM_stack_node_dummy
{
	void *m_pContent;
	struct SRM_stack_node_dummy *m_pNext;
} SRM_stack_node;

typedef struct SRM_handle_dummy
{
	int m_iFlag;
	//charset
	unsigned short *m_CharToIdxMap;
	char *m_IdxToCharMap;
	char *m_NowParseSet;
	unsigned short m_usCharSetSize;
	//match table
	SRM_node_t *m_pTable;
	//error & warning code
	int m_iErrorCode;
	int m_iErrorPos;
	int m_iErrorLine;
	int m_iWarningCode;
	int m_iWarningPos;
	int m_iWarningLine;

	char *m_pToken;	 //解析指针
	char *m_pNowStr; //但前解析的str
	char *m_pRegex;	 //正则表达式

	unsigned char m_bLastDollarChar;
	unsigned char m_bLastCaretChar;
	unsigned char m_bBeginMatch;
	unsigned char m_bEndMatch;

	SRM_keyword_t *m_pKeyWordList;
	SRM_keyword_t *m_pNowKeyWord;
	unsigned short m_usNowKeyWordSize;
	unsigned short m_usKeyWordStatFlag;
	unsigned short m_usMinKeyWordSize;
	unsigned short m_usMaxEndMatchKeyWordSize;

	SRM_stack_node *m_pResStack;
	SRM_stack_node *m_pOpStack;

	SRM_node_plink *m_pNowLink, *m_pNextLink;

} SRM_handle;

static char srm_g_DefaultCharSet[] = {' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~'};
static char srm_g_OpChar[] = {'^', '$', '\\', '|', '(', ')', '[', ']', '-', '.', '<', '>'};
static int srm_g_DefaultFlag = SRM_SYSDEFAULT_FLAG; //缺省为大小写敏感
static int srm_g_NowFlag = SRM_SYSDEFAULT_FLAG;

static void srm_parse_char(SRM_handle *handle, char c);

#ifdef SRM_MEMALLOCERR_TEST
#define SRM_MEMALLOCERR || ++srm_g_MemErrCount > srm_g_MaxMemErr
static int srm_g_MaxMemErr = 0;
static int srm_g_MemErrCount = 0;
#else
#define SRM_MEMALLOCERR
#endif

#ifdef SRM_DEBUG_SHOW_MEMALLOC_INFO
static int srm_g_NewNum = 0;
static int srm_g_AllNewNum = 0;
static int srm_g_MaxNewNum = 0;
static int srm_g_AllNewSize = 0;
static int srm_g_NewSize = 0;
static int srm_g_AllNodes = 0;

#ifdef SRM_LINUX_KERNEL
#ifdef SRM_SPIN_LOCK
static DEFINE_SPINLOCK(srm_g_lock);
#endif
#endif

static void *SRM_MALLOC(int x)
{
	void *pRes =
#ifdef SRM_LINUX_KERNEL
		kmalloc((x + sizeof(int)), GFP_KERNEL);
#else
		malloc(x + sizeof(int));
#endif
	if (pRes)
	{
		*((int *)pRes) = x;
		pRes = (char *)pRes + sizeof(int);
#ifdef SRM_LINUX_KERNEL
#ifdef SRM_SPIN_LOCK
		spin_lock(&srm_g_lock);
#endif
#endif
		srm_g_NewNum++;
		srm_g_AllNewNum++;
		srm_g_AllNewSize += x;
		srm_g_NewSize += x;
		if (srm_g_NewNum > srm_g_MaxNewNum)
			srm_g_MaxNewNum = srm_g_NewNum;

#ifdef SRM_LINUX_KERNEL
#ifdef SRM_SPIN_LOCK
		spin_unlock(&srm_g_lock);
#endif
#endif
	}
	return pRes;
}
static void SRM_FREE(void *x)
{
	if (x)
	{
		int size;
		x = (char *)x - sizeof(int);
		size = *((int *)x);

#ifdef SRM_LINUX_KERNEL
#ifdef SRM_SPIN_LOCK
		spin_lock(&srm_g_lock);
#endif
#endif

		srm_g_NewNum--;
		srm_g_NewSize -= size;

#ifdef SRM_LINUX_KERNEL
#ifdef SRM_SPIN_LOCK
		spin_unlock(&srm_g_lock);
#endif
#endif

#ifdef SRM_LINUX_KERNEL
		kfree(x);
#else
		free(x);
#endif
	}
}
#endif

static void srm_show_errors(SRM_handle *handle)
{
	if (!handle)
		return;
	switch (handle->m_iErrorCode)
	{
	case SRM_COMPILE_MEM_ERROR:
		SRM_PRINT("SRM Memory alloc error!(line:%d)\n", handle->m_iErrorLine);
		break;
	case SRM_COMPILE_BRACKETDISMATCH_ERROR:
		SRM_PRINT("SRM Bracket dismatch error!(line:%d)\n", handle->m_iErrorLine);
		break;
	case SRM_COMPILE_SQUAREBRACKETDISMATCH_ERROR:
		SRM_PRINT("SRM Square bracket dismatch error!(line:%d)\n", handle->m_iErrorLine);
		break;
	case SRM_COMPILE_ANGLEBRACKETDISMATCH_ERROR:
		SRM_PRINT("SRM Angle bracket dismatch error!(line:%d)\n", handle->m_iErrorLine);
		break;
	case SRM_COMPILE_KEYWORDVALUE_ERROR:
		SRM_PRINT("SRM Keyword value parse error!(line:%d)\n", handle->m_iErrorLine);
		break;
	case SRM_COMPILE_REFCOUNT_ERROR:
		SRM_PRINT("SRM Table node refcount error!(line:%d)\n", handle->m_iErrorLine);
		break;
	case SRM_COMPILE_SOLONGKEYWORD_ERROR:
		SRM_PRINT("SRM Keyword size is larger than %d!(line:%d)\n", MAX_KEYWORDSIZE, handle->m_iErrorLine);
		break;
	}
}

static short srm_get_escchar(SRM_handle *handle, char c)
{
	short esc;
	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return -1;
	switch (c)
	{
	case '0':
		esc = '\0';
		break;
	case 'n':
		esc = '\n';
		break;
	case 't':
		esc = '\t';
		break;
	case 'v':
		esc = '\v';
		break;
	case 'a':
		esc = '\a';
		break;
	case 'b':
		esc = '\b';
		break;
	case 'r':
		esc = '\r';
		break;
	//case 'x': '\x134' is need support?
	default:
		esc = c;
		break;
	}
	//test if the esc is in charset
	if (SRM_CHARTOIDX(handle, esc) == -1)
		return -1;
	return esc;
}

/*
res:-1 读取完毕
res>   读取的字符
*/
static short srm_get_char(SRM_handle *handle)
{
	short c;
	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return -1;
	while (1)
	{
		c = (short)(unsigned char)(*handle->m_pToken);
		if (c == 0)
			return -1;

		handle->m_pToken++;
		if (!(handle->m_iFlag & SRM_NOCASEFOLDING_FLAG))
		{
			//casefolding,convert chars to one case
			if (c >= 'a' && c <= 'z')
				c = c - 'a' + 'A';
		}
		if (handle->m_CharToIdxMap[c] == 0)
		{ //illegal字符,过滤
			SRM_SETWARNING(handle, SRM_COMPILE_ILLEGAL_CHAR_WARNING);
			continue;
		}
		return c;
	}
}

static void srm_free_keywords(SRM_keyword_t *p)
{
	SRM_keyword_t *pTemp;
	while (p)
	{
		pTemp = p->m_pNext;
		if (p->m_pStr)
			SRM_FREE(p->m_pStr);
		SRM_FREE(p);
		p = pTemp;
	}
}

static void srm_free_keywordplink(SRM_keyword_plink *pLink)
{
	SRM_keyword_plink *pTemp;
	while (pLink)
	{
		pTemp = pLink->m_pNext;
		SRM_FREE(pLink);
		pLink = pTemp;
	}
}

static void srm_free_node(SRM_node_t *pNode)
{
	if (pNode && pNode->m_uiRefCount == 0)
	{
		if (pNode->m_pCharToNextNodesIdxMap)
			SRM_FREE(pNode->m_pCharToNextNodesIdxMap);
		if (pNode->m_pMatchKeyWordLink)
			srm_free_keywordplink(pNode->m_pMatchKeyWordLink);
		if (pNode->m_ppNextNodes)
			SRM_FREE(pNode->m_ppNextNodes);
		SRM_FREE(pNode);
	}
}

static void srm_free_nodes(SRM_handle *handle, SRM_node_t *pNode)
{
	int n;
	struct srm_free_nodes_chain_s
	{
		SRM_node_t *pNode;
		unsigned short i;
	} * chain;
	if (!pNode)
		return;
	chain = (struct srm_free_nodes_chain_s *)SRM_MALLOC(MAX_KEYWORDSIZE * sizeof(*chain));
	if (!chain)
		return;
	chain[0].pNode = pNode;
	chain[0].i = 0;
	for (n = 0; n >= 0;)
	{
		SRM_node_t *pNext;
		if (chain[n].i >= handle->m_usCharSetSize)
		{
			srm_free_node(chain[n--].pNode);
			continue;
		}
		pNext = SRM_GET_NEXTNODE(chain[n].pNode, chain[n].i++);
		if (pNext)
		{
			if (--pNext->m_uiRefCount == 0 && n < MAX_KEYWORDSIZE - 1)
			{
				n++;
				chain[n].pNode = pNext;
				chain[n].i = 0;
			}
		}
	}
	SRM_FREE(chain);
}

/*
static void srm_free_nodes(SRM_handle * handle,SRM_node_t * pNode)
{
    int i;
    SRM_node_t * pNext;
    if(pNode){
        for(i=0; i< handle->m_usCharSetSize; i++){
            pNext = SRM_GET_NEXTNODE(pNode,i);
            if(pNext){
                if(--pNext->m_uiRefCount==0)
                    srm_free_nodes(handle,pNext);
            }
        }
        srm_free_node(pNode);
    }
}
*/

static void srm_free_nodeplink(SRM_node_plink *pLink)
{
	SRM_node_plink *pTemp;
	while (pLink)
	{
		pTemp = pLink->m_pNext;
		SRM_FREE(pLink);
		pLink = pTemp;
	}
}

static void srm_push_data(SRM_handle *handle, SRM_stack_node **ppStack, void *content)
{
	SRM_stack_node *pNew;
	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return;
	if (!ppStack)
		return;
	pNew = (SRM_stack_node *)SRM_MALLOC(sizeof(SRM_stack_node));
	if (!pNew)
	{
		SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
		return;
	}
	memset(pNew, 0, sizeof(SRM_stack_node));
	pNew->m_pContent = content;
	pNew->m_pNext = *ppStack;
	*ppStack = pNew;
}

static void *srm_pop_data(SRM_handle *handle, SRM_stack_node **ppStack)
{
	void *content;
	SRM_stack_node *pNow;
	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return NULL;
	if (!ppStack)
		return NULL;
	pNow = *ppStack;
	if (pNow)
	{
		*ppStack = pNow->m_pNext;
		content = pNow->m_pContent;
		SRM_FREE(pNow);
		return content;
	}
	else
		return NULL;
}

static SRM_node_t *srm_node_copy(SRM_handle *handle, SRM_node_t *src)
{
	SRM_node_t *dst;

	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return NULL;

	dst = (SRM_node_t *)SRM_MALLOC(sizeof(SRM_node_t));
	if (!dst)
		return NULL;

	if (src)
	{
		//copy content
		memcpy(dst, src, sizeof(SRM_node_t));
		//set  independent value
		dst->m_pCharToNextNodesIdxMap = NULL;
		dst->m_pMatchKeyWordLink = NULL;
		dst->m_ppNextNodes = NULL;
		dst->m_uiRefCount = 0;

		//copy chartonextnodeidxmap
		if (handle->m_usCharSetSize && src->m_pCharToNextNodesIdxMap)
		{
			dst->m_pCharToNextNodesIdxMap = (unsigned char *)SRM_MALLOC(sizeof(unsigned char) * handle->m_usCharSetSize);
			if (!dst->m_pCharToNextNodesIdxMap)
			{
				SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
				goto ERROR_PROC;
			}
			memcpy(dst->m_pCharToNextNodesIdxMap, src->m_pCharToNextNodesIdxMap, handle->m_usCharSetSize * sizeof(unsigned char));
		}
		//copy nextnodes table
		if (src->m_usNextNodesSize > 0 && src->m_ppNextNodes)
		{
			dst->m_ppNextNodes = (SRM_node_t **)SRM_MALLOC(sizeof(SRM_node_t *) * src->m_usNextNodesSize);
			if (!dst->m_ppNextNodes)
			{
				SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
				goto ERROR_PROC;
			}
			memcpy(dst->m_ppNextNodes, src->m_ppNextNodes, sizeof(SRM_node_t *) * src->m_usNextNodesSize);
		}
		//copy matchkeywordplink
		if (src->m_pMatchKeyWordLink)
		{
			SRM_keyword_plink *p, *pNew, *pLast;
			p = src->m_pMatchKeyWordLink;
			pLast = NULL;
			while (p)
			{
				pNew = (SRM_keyword_plink *)SRM_MALLOC(sizeof(SRM_keyword_plink));
				if (!pNew)
				{
					SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
					goto ERROR_PROC;
				}
				memset(pNew, 0, sizeof(SRM_keyword_plink));
				pNew->m_pKeyWord = p->m_pKeyWord;
				pNew->m_uiFlag = p->m_uiFlag;
				//正向copy
				if (pLast)
				{
					pLast->m_pNext = pNew;
					pLast = pNew;
				}
				else
				{
					dst->m_pMatchKeyWordLink = pNew;
					pLast = pNew;
				}
				p = p->m_pNext;
			}
		}
	}
	else
	{
		memset(dst, 0, sizeof(SRM_node_t));
		dst->m_uiFlag = SRM_NOTSET;

		if (handle->m_usCharSetSize)
		{
			dst->m_pCharToNextNodesIdxMap = (unsigned char *)SRM_MALLOC(sizeof(unsigned char) * handle->m_usCharSetSize);
			if (!dst->m_pCharToNextNodesIdxMap)
			{
				SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
				goto ERROR_PROC;
			}
			memset(dst->m_pCharToNextNodesIdxMap, 0, sizeof(unsigned char) * handle->m_usCharSetSize);
		}
		dst->m_usNextNodesSize = SRM_GET_NEXTNODESGOODLEN(1);
		dst->m_usNextNodesUsedNum = 1; //所有的指针都指向0，表示空
		dst->m_ppNextNodes = (SRM_node_t **)SRM_MALLOC(sizeof(SRM_node_t *) * dst->m_usNextNodesSize);
		if (!dst->m_ppNextNodes)
		{
			SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
			goto ERROR_PROC;
		}
		memset(dst->m_ppNextNodes, 0, sizeof(SRM_node_t *) * dst->m_usNextNodesSize);
	}
#ifdef SRM_DEBUG_INFO
#ifdef SRM_DEBUG_SHOW_MEMALLOC_INFO
	srm_g_AllNodes++;
#endif
#endif
	return dst;
ERROR_PROC:
	srm_free_node(dst);
	return NULL;
}

static int srm_set_nextnode(SRM_handle *handle, SRM_node_t *pNode, unsigned char idx, SRM_node_t *pNext)
{
	int i;
	int bNeedDel, bNotEqual;
	int iOldNDIdx, iNewNDIdx;
	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return -1;

	bNeedDel = 1;
	iOldNDIdx = 0;
	bNotEqual = 1;
	iNewNDIdx = 0;
	//首先 oldNDIdx need del?
	iOldNDIdx = SRM_GET_NEXTNODEIDX(pNode, idx);
	if (SRM_GET_NEXTNODE(pNode, idx))
	{
		for (i = 0; i < handle->m_usCharSetSize; i++)
		{
			if (i != idx && SRM_GET_NEXTNODE(pNode, idx) == SRM_GET_NEXTNODE(pNode, i))
				break;
		}
		if (i < handle->m_usCharSetSize)
		{
			bNeedDel = 0;
		}
	}
	else
	{
		bNeedDel = 0;
	}

	//查找是否已经有相同的pNext
	for (i = 0; i < handle->m_usCharSetSize; i++)
	{
		if (pNext == SRM_GET_NEXTNODE(pNode, i))
			break;
	}
	if (i < handle->m_usCharSetSize)
	{
		bNotEqual = 0;
		iNewNDIdx = SRM_GET_NEXTNODEIDX(pNode, i);
	}

	if (bNeedDel && bNotEqual)
	{
		//需要删除，同时没有和pNext相同的,只需要替换就可以了
		pNode->m_ppNextNodes[iOldNDIdx] = pNext;
		return 1;
	}
	else if (bNeedDel && !bNotEqual)
	{
		//需要删除，同时具有和pNext相同的,需要删除原来的,并且将指针移动到新的地方
		//del
		if (pNode->m_ppNextNodes[iOldNDIdx])
		{
			pNode->m_ppNextNodes[iOldNDIdx] = NULL;
			pNode->m_usNextNodesUsedNum--;
		}
		pNode->m_pCharToNextNodesIdxMap[idx] = iNewNDIdx;
		return 1;
	}
	else if (!bNeedDel && !bNotEqual)
	{
		//不需要删除，同时具有和pNext相同的,将指针移动到新的地方
		pNode->m_pCharToNextNodesIdxMap[idx] = iNewNDIdx;
		return 1;
	}
	else if (!bNeedDel && bNotEqual)
	{
		//不需要删除，同时不具有和pNext相同的,需要创建一个新的,并且将指针移动到新的地方
		//new
		if (pNode->m_usNextNodesUsedNum >= pNode->m_usNextNodesSize)
		{
			//需要扩大pNode->m_usNextNodesSize
			int iNewSize;
			SRM_node_t **ppNewBuf;
			iNewSize = SRM_GET_NEXTNODESGOODLEN(pNode->m_usNextNodesSize + 1);
			ppNewBuf = (SRM_node_t **)SRM_MALLOC(sizeof(SRM_node_t *) * iNewSize);
			if (!ppNewBuf)
			{
				SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
				return -1;
			}
			memset(ppNewBuf, 0, sizeof(SRM_node_t *) * iNewSize);
			memcpy(ppNewBuf, pNode->m_ppNextNodes, sizeof(SRM_node_t *) * pNode->m_usNextNodesSize);
			pNode->m_usNextNodesSize = iNewSize;
			SRM_FREE(pNode->m_ppNextNodes);
			pNode->m_ppNextNodes = ppNewBuf;
		}
		for (i = 1; i < pNode->m_usNextNodesSize; i++)
		{
			if (!pNode->m_ppNextNodes[i])
			{
				//除了第一个缺省的为NULL表示下一个节点不存在，其它的NULL表示未用
				pNode->m_pCharToNextNodesIdxMap[idx] = i;
				pNode->m_ppNextNodes[i] = pNext;
				pNode->m_usNextNodesUsedNum++;
				return 1;
			}
		}
	}
	return 1;
}

static void srm_parse_charset(SRM_handle *handle, char *charset, int num)
{
	//parse a char set

	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return;

	if (!charset || num <= 0 || num > handle->m_usCharSetSize)
		return;

	//process last $
	if (handle->m_bLastDollarChar)
	{
		handle->m_bLastDollarChar = 0;
		srm_parse_char(handle, '$');
	}

	{
		//add the char set the all nownode in nowlink
		SRM_node_plink *itp;
		short idx;
		int i, j;
		SRM_node_t *pNextNode, *pNode;
		char charsetProcessed[MAX_CHAR];

		itp = handle->m_pNowLink;
		while (itp)
		{
			pNode = itp->m_pNode;

			memset(charsetProcessed, 0, sizeof(charsetProcessed));
			for (i = 0; i < num; i++)
			{

				pNextNode = NULL;
				if (charsetProcessed[i])
					continue;
				idx = SRM_CHARTOIDX(handle, charset[i]);
				charsetProcessed[i] = 1;
				if (idx < 0)
				{
					SRM_SETWARNING(handle, SRM_COMPILE_ILLEGAL_CHAR_WARNING);
					continue;
				}
				pNextNode = SRM_GET_NEXTNODE(pNode, idx);
				if (pNextNode)
				{
					if (pNextNode->m_uiRefCount == 1)
					{
						//直接重用
					}
					else if (pNextNode->m_uiRefCount <= 0)
					{
						SRM_SETERROR(handle, SRM_COMPILE_REFCOUNT_ERROR);
						return;
					}
					else
					{ //refcount>1
						//查找是否指向他的节点都是来自于本集合的字符
						int count = 0;
						for (j = i; j < num; j++)
						{
							idx = SRM_CHARTOIDX(handle, charset[j]);
							if (idx < 0)
							{
								SRM_SETWARNING(handle, SRM_COMPILE_ILLEGAL_CHAR_WARNING);
								continue;
							}
							if (pNextNode == SRM_GET_NEXTNODE(pNode, idx))
								count++;
						}
						if (count < (int)pNextNode->m_uiRefCount)
						{
							//还有其他集合的字符
							//need to copy one
							SRM_node_t *pNew = srm_node_copy(handle, pNextNode);
							if (!pNew)
							{
								SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
								return;
							}

							for (j = i; j < num; j++)
							{
								idx = SRM_CHARTOIDX(handle, charset[j]);
								if (idx < 0)
								{
									SRM_SETWARNING(handle, SRM_COMPILE_ILLEGAL_CHAR_WARNING);
									continue;
								}
								if (pNextNode == SRM_GET_NEXTNODE(pNode, idx))
								{
									//旧的后续节点 refcount-1,新的后续节点refcount+1
									if (srm_set_nextnode(handle, pNode, (unsigned char)idx, pNew) == -1)
									{
										srm_free_node(pNew);
										return;
									}
									pNew->m_uiRefCount++;
									pNextNode->m_uiRefCount--;
									charsetProcessed[j] = 1;
								}
							}
							{
								//新的后续节点的所有连接节点refcount+1
								int k;
								SRM_node_t *pTemp;
								for (k = 0; k < handle->m_usCharSetSize; k++)
								{
									pTemp = SRM_GET_NEXTNODE(pNew, k);
									if (pTemp)
										pTemp->m_uiRefCount++;
								}
							}
							pNextNode = pNew;
						}
						else
						{
							for (j = i; j < num; j++)
							{
								idx = SRM_CHARTOIDX(handle, charset[j]);
								if (idx < 0)
								{
									SRM_SETWARNING(handle, SRM_COMPILE_ILLEGAL_CHAR_WARNING);
									continue;
								}
								if (pNextNode == SRM_GET_NEXTNODE(pNode, idx))
								{
									charsetProcessed[j] = 1;
								}
							}
						}
					}
				}
				else
				{ //empty, new one, all empty char use one new node
					SRM_node_t *pNew = srm_node_copy(handle, NULL);
					if (!pNew)
					{
						SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
						return;
					}
					for (j = i; j < num; j++)
					{
						idx = SRM_CHARTOIDX(handle, charset[j]);
						if (idx < 0)
						{
							SRM_SETWARNING(handle, SRM_COMPILE_ILLEGAL_CHAR_WARNING);
							continue;
						}
						if (!SRM_GET_NEXTNODE(pNode, idx))
						{
							if (srm_set_nextnode(handle, pNode, (unsigned char)idx, pNew) == -1)
							{
								srm_free_node(pNew);
								return;
							}
							pNew->m_uiRefCount++;
							charsetProcessed[j] = 1;
						}
					}
					pNextNode = pNew;
				}
				{
					//first we find if it has exit in the res set
					SRM_node_plink *pTemp = handle->m_pNextLink;
					while (pTemp)
					{
						if (pTemp->m_pNode == pNextNode)
							break;
						pTemp = pTemp->m_pNext;
					}
					if (!pTemp)
					{
						//将下一个节点加入nextlink集合
						pTemp = (SRM_node_plink *)SRM_MALLOC(sizeof(SRM_node_plink));
						if (!pTemp)
						{
							SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
							return;
						}
						memset(pTemp, 0, sizeof(SRM_node_plink));
						pTemp->m_pNode = pNextNode;
						pTemp->m_pNext = handle->m_pNextLink;
						handle->m_pNextLink = pTemp;
					}
				}
			}
			itp = itp->m_pNext;
		}
	}
	{
		//go ahead
		srm_free_nodeplink(handle->m_pNowLink);
		handle->m_pNowLink = handle->m_pNextLink;
		handle->m_pNextLink = NULL;

		handle->m_usNowKeyWordSize++;
	}
}

static void srm_parse_char(SRM_handle *handle, char c)
{
	char a[1];
	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return;
	a[0] = c;
	srm_parse_charset(handle, a, 1);
}

static void srm_parse_dot(SRM_handle *handle)
{
	int i;
	char charset[MAX_CHAR];
	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return;
	memset(charset, 0, sizeof(char) * MAX_CHAR);
	//设置所有字符集中的字符
	for (i = 0; i < handle->m_usCharSetSize; i++)
	{
		charset[i] = handle->m_IdxToCharMap[i];
	}
	srm_parse_charset(handle, charset, handle->m_usCharSetSize);
}

static void srm_parse_squarebracket(SRM_handle *handle)
{
	//读取到']'
	//里面的操作符号只有打头的^,-
	//特殊字符[,],-
	//为了与gnu兼容，我们在[]中不支持\转义
	int bEnd;
	int bFirst;	  //是否为第一个字符
	int bReverse; //是否取反
	int bHyphen;  //最后一个字符是否为'-'
	int lastIdx;  //最后一个非'-'字符

	short c;
	short idx;
	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return;

	if (!handle->m_pNowKeyWord)
		return;

	bEnd = 0;
	bFirst = 1;
	bReverse = 0;
	bHyphen = 0;
	lastIdx = -1;
	memset(handle->m_NowParseSet, 0, sizeof(char) * handle->m_usCharSetSize);

	while (!bEnd && handle->m_iErrorCode == SRM_COMPILE_NOERROR)
	{
		c = srm_get_char(handle);
		switch (c)
		{
		case -1:
		{
			//结束字,没有读取到']',syntaxerror
			SRM_SETERROR(handle, SRM_COMPILE_SQUAREBRACKETDISMATCH_ERROR);
			bEnd = 1;
			continue;
		}
		break;
		case '^':
		{
			if (bFirst)
			{
				//^取反操作符
				bReverse = 1;
				bFirst = 0;
				continue;
			}
		}
		break;
		case ']':
		{
			bFirst = 0;
			bEnd = 1;
			continue;
		}
		break;
		case '-':
		{
			//前面没有字符或者后面没有字符的，我们认为是'-'字符
			bFirst = 0;
			if (lastIdx == -1)
			{
				//这个是'-'字符
			}
			else if (bHyphen)
			{
				//这个是'-'字符
			}
			else
			{
				//这个可能是'-'操作符,还需要看后面的字符是否存在
				bHyphen = 1;
				continue;
			}
		}
		break;
		case '\\':
		{
			bFirst = 0;
			/*c = srm_get_char(handle);
                //结束字,没有读取到']',syntaxerror
                if(c==-1){
                    SRM_SETERROR(handle,SRM_COMPILE_SQUAREBRACKETDISMATCH_ERROR);					
                    bEnd = 1;
                    continue;
                }
                c = srm_get_escchar(handle,(char)c);
                //不在charsetmap中，该字符抛弃
                if(c==-1)
                    continue;*/
		}
		break;
		default:
		{
			bFirst = 0;
		}
		break;
		}
		idx = SRM_CHARTOIDX(handle, c);
		if (idx < 0)
		{
			SRM_SETWARNING(handle, SRM_COMPILE_ILLEGAL_CHAR_WARNING);
			continue;
		}
		if (lastIdx != -1 && bHyphen)
		{
			//前面有一个字符和'-'，加上当前字符，a-b ok
			int i;
			for (i = lastIdx; i <= idx; i++)
			{
				handle->m_NowParseSet[i] = 1;
			}
			lastIdx = -1;
			bHyphen = 0;
		}
		else
		{
			if (lastIdx != -1)
			{
				handle->m_NowParseSet[lastIdx] = 1;
				lastIdx = -1;
			}
			if (bHyphen)
			{
				int hyphenIdx = SRM_CHARTOIDX(handle, '-');
				handle->m_NowParseSet[hyphenIdx] = 1;
				bHyphen = 0;
			}
			lastIdx = idx;
		}
	}
	if (lastIdx != -1)
	{
		handle->m_NowParseSet[lastIdx] = 1;
		lastIdx = -1;
	}
	if (bHyphen)
	{
		int hyphenIdx = SRM_CHARTOIDX(handle, '-');
		handle->m_NowParseSet[hyphenIdx] = 1;
		bHyphen = 0;
	}
	if (handle->m_iErrorCode == SRM_COMPILE_NOERROR)
	{
		char charset[MAX_CHAR];
		int i, size;
		memset(charset, 0, sizeof(char) * MAX_CHAR);
		for (i = 0, size = 0; i < handle->m_usCharSetSize; i++)
		{
			if (bReverse)
				handle->m_NowParseSet[i] = 1 - handle->m_NowParseSet[i];
			if (handle->m_NowParseSet[i])
				charset[size++] = SRM_IDXTOCHAR(handle, i);
		}
		srm_parse_charset(handle, charset, size);
	}
}

static void srm_parse_anglebracket(SRM_handle *handle)
{
	int bEnd;
	unsigned int uiValue;
	short c;
	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return;
	if (!handle->m_pNowKeyWord)
		return;
	bEnd = 0;
	uiValue = 0;
	while (!bEnd && handle->m_iErrorCode == SRM_COMPILE_NOERROR)
	{
		c = srm_get_char(handle);
		switch (c)
		{
		case -1:
		{
			//结束字,没有读取到'>',syntaxerror
			SRM_SETERROR(handle, SRM_COMPILE_ANGLEBRACKETDISMATCH_ERROR);
			bEnd = 1;
			continue;
		}
		break;
		case '>':
		{
			//结束
			bEnd = 1;
			continue;
		}
		break;
		case '\\':
		{
			c = srm_get_char(handle);
			//结束字,没有读取到'>',syntaxerror
			if (c == -1)
			{
				SRM_SETERROR(handle, SRM_COMPILE_ANGLEBRACKETDISMATCH_ERROR);
				bEnd = 1;
				continue;
			}
			c = srm_get_escchar(handle, (char)c);
			if (c == -1) //不在charsetmap中，该字符抛弃
				continue;
		}
		break;
		default:
			break;
		}
		if (c >= '0' && c <= '9')
		{
			uiValue = uiValue * 10 + (c - '0');
		}
		else
		{
			SRM_SETERROR(handle, SRM_COMPILE_KEYWORDVALUE_ERROR);
			bEnd = 1;
			continue;
		}
	}
	if (handle->m_iErrorCode == SRM_COMPILE_NOERROR)
	{
		handle->m_pNowKeyWord->m_uiValue = uiValue;
	}
}

static void srm_parse_keyword_end(SRM_handle *handle)
{
	SRM_node_plink *p;
	SRM_node_t *pNode;
	//设置结果集的flag和可以匹配的关键字
	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return;

	if (!handle->m_pNowKeyWord)
		return;

	if (handle->m_bLastDollarChar)
	{
		handle->m_bEndMatch = 1;
		handle->m_bLastDollarChar = 0;
	}
	p = handle->m_pNowLink;
	while (p)
	{
		pNode = p->m_pNode;
		if (pNode)
		{
			//set node end flag
			if (pNode->m_uiFlag & SRM_NOTSET)
			{
				pNode->m_uiFlag &= ~SRM_NOTSET;
				if (handle->m_bBeginMatch)
					pNode->m_uiFlag |= SRM_BEGINMATCH;
				if (handle->m_bEndMatch)
					pNode->m_uiFlag |= SRM_ENDMATCH;
			}
			else
			{
				if (!handle->m_bBeginMatch)
					pNode->m_uiFlag &= ~SRM_BEGINMATCH;
				if (!handle->m_bEndMatch)
					pNode->m_uiFlag &= ~SRM_ENDMATCH;
			}
			pNode->m_uiFlag |= SRM_NODE_END;
			//设置matchkeywordlink
			{
				SRM_keyword_plink *pKeyWordLink;
				pKeyWordLink = pNode->m_pMatchKeyWordLink;
				while (pKeyWordLink)
				{
					if (pKeyWordLink->m_pKeyWord == handle->m_pNowKeyWord)
						break;
					pKeyWordLink = pKeyWordLink->m_pNext;
				}
				if (!pKeyWordLink)
				{
					//没有相同的keyword
					pKeyWordLink = (SRM_keyword_plink *)SRM_MALLOC(sizeof(SRM_keyword_plink));
					if (!pKeyWordLink)
					{
						SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
						return;
					}
					memset(pKeyWordLink, 0, sizeof(SRM_keyword_plink));
					pKeyWordLink->m_pKeyWord = handle->m_pNowKeyWord;
					pKeyWordLink->m_uiFlag = SRM_NODE_END | (handle->m_bBeginMatch ? SRM_BEGINMATCH : 0) | (handle->m_bEndMatch ? SRM_ENDMATCH : 0);
					pKeyWordLink->m_pNext = pNode->m_pMatchKeyWordLink;
					pNode->m_pMatchKeyWordLink = pKeyWordLink;
				}
			}
		}
		p = p->m_pNext;
	}
	//set the stat info
	if (handle->m_bBeginMatch)
	{
		handle->m_usKeyWordStatFlag |= SRM_BEGINMATCH_STATFLAG;
	}
	else if (handle->m_bEndMatch)
	{
		//if it has not '^' and it has '$' then endmatch_statflag
		handle->m_usKeyWordStatFlag |= SRM_ENDMATCH_STATFLAG;
		if (handle->m_usMaxEndMatchKeyWordSize < handle->m_usNowKeyWordSize)
			handle->m_usMaxEndMatchKeyWordSize = handle->m_usNowKeyWordSize;
	}
	else
	{
		//if it has not '^' and '$' then other_statflag
		handle->m_usKeyWordStatFlag |= SRM_OTHERMATCH_STATFLAG;
	}
	if (handle->m_usMinKeyWordSize > handle->m_usNowKeyWordSize)
		handle->m_usMinKeyWordSize = handle->m_usNowKeyWordSize;

	srm_free_nodeplink(handle->m_pNowLink);
	handle->m_pNowLink = NULL;
}

static void srm_parse_keyword(SRM_handle *handle)
{
	//分析关键字
	short c;
	int bEnd, bFirst, bRealFirst;

	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return;

	if (!handle->m_pNowKeyWord || !handle->m_pNowKeyWord->m_pStr)
		return;

	//init
	handle->m_pNowStr = handle->m_pNowKeyWord->m_pStr;
	handle->m_pToken = handle->m_pNowStr;

	handle->m_pNowLink = (SRM_node_plink *)SRM_MALLOC(sizeof(SRM_node_plink));
	if (!handle->m_pNowLink)
	{
		SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
		return;
	}
	memset(handle->m_pNowLink, 0, sizeof(SRM_node_plink));
	handle->m_pNowLink->m_pNode = handle->m_pTable;
	handle->m_pNextLink = NULL;

	handle->m_usNowKeyWordSize = 0;

	handle->m_bLastDollarChar = 0;
	handle->m_bLastCaretChar = 0;
	handle->m_bBeginMatch = 0;
	handle->m_bEndMatch = 0;

	bRealFirst = 1;
	bFirst = 1;
	bEnd = 0;

	while (!bEnd && handle->m_iErrorCode == SRM_COMPILE_NOERROR)
	{
		c = srm_get_char(handle);
		switch (c)
		{
		case -1:
		{
			//结束
			bEnd = 1;
			continue;
		}
		break;
		case '<':
		{
			// '<>'必须在最前面
			if (bRealFirst)
			{
				bRealFirst = 0;
				//'<'操作符
				srm_parse_anglebracket(handle);
				continue;
			}
			//一般字符
		}
		break;
		case '\\':
		{
			//非[]之内
			//'\'符号是转义符,我们需要再获取一个
			bRealFirst = 0;
			bFirst = 0;
			c = srm_get_char(handle);
			if (c == -1)
			{
				bEnd = 1;
				continue;
			}
			c = srm_get_escchar(handle, (char)c);
			//不在charsetmap中，该字符抛弃
			if (c == -1)
				continue;
		}
		break;
		case '^':
		{
			bRealFirst = 0;
			//在最前面或者在<>操作符后面
			if (bFirst)
			{
				bFirst = 0;
				//最前面,是^操作符
				handle->m_bBeginMatch = 1;
				continue;
			}
			//一般字符
		}
		break;
		case '$':
		{
			bRealFirst = 0;
			bFirst = 0;
			if (handle->m_bLastDollarChar)
			{
				handle->m_bLastDollarChar = 0;
				srm_parse_char(handle, '$');
			}
			handle->m_bLastDollarChar = 1;
			continue;
		}
		break;
		case '.':
		{
			bRealFirst = 0;
			bFirst = 0;
			srm_parse_dot(handle);
			continue;
		}
		break;
		case '[':
		{
			bRealFirst = 0;
			bFirst = 0;
			srm_parse_squarebracket(handle);
			continue;
		}
		break;
		default:
		{
			bRealFirst = 0;
			bFirst = 0;
		}
		break;
		}
		srm_parse_char(handle, (char)((unsigned char)c));
	}
	if (handle->m_iErrorCode == SRM_COMPILE_NOERROR)
		srm_parse_keyword_end(handle);
	else
	{
		//error,clear the result sets
		srm_free_nodeplink(handle->m_pNowLink);
		handle->m_pNowLink = NULL;
		srm_free_nodeplink(handle->m_pNextLink);
		handle->m_pNextLink = NULL;
	}
}

static short srm_read_cell(SRM_handle *handle)
{
	int bData, bEnd, bBackslash;
	SRM_keyword_t *pData;
	short c;
	char *nowToken1, *nowToken2;
	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return -1;

	bData = 0;
	bBackslash = 0;
	bEnd = 0;
	pData = NULL;
	while (!bEnd && handle->m_iErrorCode == SRM_COMPILE_NOERROR)
	{
		nowToken1 = handle->m_pToken;
		c = srm_get_char(handle);
		switch (c)
		{
		case -1:
		{
			if (bData)
			{
				bEnd = 1;
				continue;
			}
			else
				return -1;
		}
		break;
		case '\\':
		{
			if (!bBackslash)
			{
				//'\'符号是转义符,我们需要再获取一个
				nowToken2 = handle->m_pToken;
				c = srm_get_char(handle);
				if (c == -1)
				{ //结束
					if (bData)
					{
						bEnd = 1;
						continue;
					}
					else
						return -1;
				}
				if (c == '|' || c == '(' || c == ')')
				{
					//操作符，前面都需要'\\'
					if (bData)
					{
						handle->m_pToken = nowToken1; //回朔到开始
						bEnd = 1;
						continue;
					}
					else
					{
						return c;
					}
				}
				else if (c == '\\')
				{
					handle->m_pToken = nowToken2;
					bBackslash = 1;
					//c = '\\';
				}
				else
				{
					//其它字符,退后一步,写入'\',这里不做转义,下次写入这个字符
					handle->m_pToken = nowToken2;
					c = '\\';
				}
			}
			else
			{
				//上次也是'\\',这次直接写入'\\'
				bBackslash = 0;
				//c = '\\';
			}
		}
		break;
		default:
			break;
		}
		bData = 1;
		if (!pData)
		{
			int newLen;
			pData = (SRM_keyword_t *)SRM_MALLOC(sizeof(SRM_keyword_t));
			if (!pData)
			{
				SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
				continue;
			}
			memset(pData, 0, sizeof(SRM_keyword_t));
			newLen = SRM_GET_STRBUFGOODLEN(1);
			pData->m_pStr = (char *)SRM_MALLOC(newLen);
			if (!pData->m_pStr)
			{
				SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
				continue;
			}
			memset(pData->m_pStr, 0, newLen);
			pData->m_iStrBufLen = newLen;
		}
		if (SRM_GET_STRBUFGOODLEN(pData->m_iStrLen + 1 + 1) > pData->m_iStrBufLen)
		{
			//strlen + \0 + newchar buflen > nowbuflen
			char *newBuf;
			int newLen;
			newLen = SRM_GET_STRBUFGOODLEN(pData->m_iStrLen + 1 + 1);
			newBuf = (char *)SRM_MALLOC(newLen);
			if (!newBuf)
			{
				SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
				continue;
			}
			memset(newBuf, 0, newLen);
			memcpy(newBuf, pData->m_pStr, pData->m_iStrLen);
			SRM_FREE(pData->m_pStr);
			pData->m_pStr = newBuf;
			pData->m_iStrBufLen = newLen;
		}
		pData->m_pStr[pData->m_iStrLen++] = (char)c;
	}
	if (handle->m_iErrorCode == SRM_COMPILE_NOERROR)
	{
		srm_push_data(handle, &handle->m_pResStack, (void *)pData);
	}
	if (handle->m_iErrorCode == SRM_COMPILE_NOERROR)
	{
		return 'd';
	}
	else
	{
		if (pData)
		{
			if (pData->m_pStr)
				SRM_FREE(pData->m_pStr);
			SRM_FREE(pData);
		}
		return -1;
	}
}

static void srm_do_add(SRM_handle *handle)
{
	SRM_keyword_t *pdata1, *pdata2, *pRes, *pit1, *pit2, *pNew;
	int newLen;
	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return;

	pRes = NULL;

	//pop two data and add them then push it to stack
	pdata2 = (SRM_keyword_t *)srm_pop_data(handle, &handle->m_pResStack);
	pdata1 = (SRM_keyword_t *)srm_pop_data(handle, &handle->m_pResStack);

	if (!pdata1 && pdata2)
	{
		pRes = pdata2;
		SRM_SETWARNING(handle, SRM_COMPILE_SYNTAX_WARNING);
	}
	else if (!pdata2 && pdata1)
	{
		pRes = pdata1;
		SRM_SETWARNING(handle, SRM_COMPILE_SYNTAX_WARNING);
	}
	else if (!pdata1 && !pdata2)
	{
		SRM_SETWARNING(handle, SRM_COMPILE_SYNTAX_WARNING);
		return;
	}
	else
	{
		pit1 = pdata1;
		while (pit1)
		{
			pit2 = pdata2;
			while (pit2)
			{
				pNew = (SRM_keyword_t *)SRM_MALLOC(sizeof(SRM_keyword_t));
				if (!pNew)
				{
					SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
					goto ERROR_PROC;
				}
				memset(pNew, 0, sizeof(SRM_keyword_t));
				newLen = SRM_GET_STRBUFGOODLEN(pit1->m_iStrLen + pit2->m_iStrLen + 1);
				pNew->m_pStr = (char *)SRM_MALLOC(newLen);
				if (!pNew->m_pStr)
				{
					SRM_FREE(pNew);
					SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
					goto ERROR_PROC;
				}
				pNew->m_iStrBufLen = newLen;
				memset(pNew->m_pStr, 0, newLen);
				memcpy(pNew->m_pStr, pit1->m_pStr, pit1->m_iStrLen);
				pNew->m_iStrLen += pit1->m_iStrLen;
				memcpy(pNew->m_pStr + pNew->m_iStrLen, pit2->m_pStr, pit2->m_iStrLen);
				pNew->m_iStrLen += pit2->m_iStrLen;

				if (!pRes)
				{
					pRes = pNew;
				}
				else
				{
					pNew->m_pNext = pRes;
					pRes = pNew;
				}

				pit2 = pit2->m_pNext;
			}
			pit1 = pit1->m_pNext;
		}
		srm_free_keywords(pdata1);
		pdata1 = NULL;
		srm_free_keywords(pdata2);
		pdata2 = NULL;
	}
	srm_push_data(handle, &handle->m_pResStack, (void *)pRes);
	if (handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		goto ERROR_PROC;
	return;
ERROR_PROC:
	srm_free_keywords(pdata1);
	srm_free_keywords(pdata2);
	srm_free_keywords(pRes);
}

static void srm_do_union(SRM_handle *handle)
{
	SRM_keyword_t *pdata1, *pdata2, *pRes, *pit1, *pit2;
	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return;

	pRes = NULL;

	//pop two data and add them then push it to stack
	pdata2 = (SRM_keyword_t *)srm_pop_data(handle, &handle->m_pResStack);
	pdata1 = (SRM_keyword_t *)srm_pop_data(handle, &handle->m_pResStack);

	if (!pdata1 && pdata2)
	{
		pRes = pdata2;
		SRM_SETWARNING(handle, SRM_COMPILE_SYNTAX_WARNING);
	}
	else if (!pdata2 && pdata1)
	{
		pRes = pdata1;
		SRM_SETWARNING(handle, SRM_COMPILE_SYNTAX_WARNING);
	}
	else if (!pdata1 && !pdata2)
	{
		SRM_SETWARNING(handle, SRM_COMPILE_SYNTAX_WARNING);
		return;
	}
	else
	{
		pRes = pdata1;
		pit1 = pdata1;
		pit2 = pdata1->m_pNext;
		while (pit2)
		{
			pit1 = pit2;
			pit2 = pit2->m_pNext;
		}
		pit1->m_pNext = pdata2;
	}
	srm_push_data(handle, &handle->m_pResStack, (void *)pRes);
	if (handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		srm_free_keywords(pRes);
}

static void srm_do_op(SRM_handle *handle, char op)
{
	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return;
	switch (op)
	{
	case '(':
	{
		//push ( ;
		srm_push_data(handle, &handle->m_pOpStack, (void *)(int)'(');
	}
	break;
	case ')':
	{
		//pop all until '('
		while (1)
		{
			char top_op = (char)(long)srm_pop_data(handle, &handle->m_pOpStack);
			if (top_op == 0)
			{
				// () 个数不匹配，错误，退出
				SRM_SETERROR(handle, SRM_COMPILE_BRACKETDISMATCH_ERROR);
				break;
			}
			else if (top_op == '(')
			{
				//good ,匹配()
				break;
			}
			else if (top_op == '+')
				srm_do_add(handle);
			else if (top_op == '|')
				srm_do_union(handle);
		}
	}
	break;
	case '+':
	{
		char top_op = (char)(long)srm_pop_data(handle, &handle->m_pOpStack);
		if (top_op == '|')
		{
			srm_push_data(handle, &handle->m_pOpStack, (void *)(long)top_op);
		}
		else if (top_op == '+')
		{
			srm_do_add(handle);
		}
		else if (top_op != 0)
		{
			srm_push_data(handle, &handle->m_pOpStack, (void *)(long)top_op);
		}
		else
		{
		}
		srm_push_data(handle, &handle->m_pOpStack, (void *)(int)'+');
	}
	break;
	case '|':
	{
		char top_op = (char)(long)srm_pop_data(handle, &handle->m_pOpStack);
		if (top_op == '|')
		{
			srm_do_union(handle);
		}
		else if (top_op == '+')
		{
			srm_do_add(handle);
		}
		else if (top_op != 0)
		{
			srm_push_data(handle, &handle->m_pOpStack, (void *)(long)top_op);
		}
		else
		{
		}
		srm_push_data(handle, &handle->m_pOpStack, (void *)(int)'|');
	}
	break;
	case 0:
	{
		while (1)
		{
			char top_op = (char)(long)srm_pop_data(handle, &handle->m_pOpStack);
			if (top_op == 0)
			{
				break;
			}
			if (top_op == '(')
			{
				// () 个数不匹配，错误，退出
				SRM_SETERROR(handle, SRM_COMPILE_BRACKETDISMATCH_ERROR);
				break;
			}
			if (top_op == '+')
			{
				srm_do_add(handle);
			}
			if (top_op == '|')
				srm_do_union(handle);
		}
	}
	break;
	}
}

static void srm_parse_regex_to_keywords(SRM_handle *handle)
{
	//将regex表达式去除 '\\|'操作符和'(',')'操作符,结果集和为若干个关键字的集合
	//创建'+'的条件 )d ; d( ; )(
	short lastres = 0;
	int bEnd = 0;

	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return;

	handle->m_pToken = handle->m_pRegex;
	handle->m_pNowStr = handle->m_pRegex;

	while (!bEnd && handle->m_iErrorCode == SRM_COMPILE_NOERROR)
	{
		short res = srm_read_cell(handle);
		switch (res)
		{
		case 'd':
		{
			//数据
			//上次读取')',创建'+'
			if (lastres == ')')
			{
				srm_do_op(handle, '+');
			}
		}
		break;
		case '(':
		{
			//'(' 操作符
			//上次读取到'd'或')',创建'+'
			if (lastres == 'd' || lastres == ')')
			{
				srm_do_op(handle, '+');
			}
			srm_do_op(handle, '(');
		}
		break;
		case ')':
		{
			srm_do_op(handle, ')');
		}
		break;
		case '|':
		{
			srm_do_op(handle, '|');
		}
		break;
		case -1:
		{
			//结束，将栈中的操作符和操作数弹出计算
			srm_do_op(handle, 0);
			bEnd = 1;
			continue;
		}
		break;
		}
		lastres = res;
	}
}

static void srm_build_charsetmap(SRM_handle *handle, char *charset, int charnum)
{
	int i, count;
	unsigned char *ucCharset;
	int opcharsetsize;

	if (!handle || handle->m_iErrorCode != SRM_COMPILE_NOERROR)
		return;

	//set the char set
	if (!charset || charnum <= 0)
	{
		charset = srm_g_DefaultCharSet;
		charnum = sizeof(srm_g_DefaultCharSet) / sizeof(char);
	}

	//build the chartoidx
	handle->m_CharToIdxMap = (unsigned short *)SRM_MALLOC(sizeof(unsigned short) * MAX_CHAR);
	if (!handle->m_CharToIdxMap)
	{
		SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
		return;
	}
	memset(handle->m_CharToIdxMap, 0, MAX_CHAR * sizeof(unsigned short));

	ucCharset = (unsigned char *)charset;
	for (i = 0; i < charnum; i++)
	{
		handle->m_CharToIdxMap[ucCharset[i]] = 1;
	}
	ucCharset = (unsigned char *)srm_g_OpChar;
	opcharsetsize = sizeof(srm_g_OpChar) / sizeof(char);
	for (i = 0; i < opcharsetsize; i++)
	{
		handle->m_CharToIdxMap[ucCharset[i]] = 1;
	}
	if (handle->m_iFlag & SRM_NOCASEFOLDING_FLAG)
	{
		//大小写敏感
		count = 1;
		for (i = 0; i < MAX_CHAR; i++)
		{
			if (handle->m_CharToIdxMap[i])
			{
				handle->m_CharToIdxMap[i] = count++;
			}
		}
	}
	else
	{
		//大小写不敏感
		//大小写中有一个在集合中，就两个都在集合中
		for (i = 'A'; i <= 'Z'; i++)
		{
			int j = i - 'A' + 'a';
			if (handle->m_CharToIdxMap[i] || handle->m_CharToIdxMap[j])
			{
				handle->m_CharToIdxMap[i] = handle->m_CharToIdxMap[j] = 1;
			}
		}
		count = 1;
		//大小写指向同一个idx
		for (i = 0; i < MAX_CHAR; i++)
		{
			if (i >= 'a' && i <= 'z')
			{
				handle->m_CharToIdxMap[i] = handle->m_CharToIdxMap[i - 'a' + 'A'];
				continue;
			}
			if (handle->m_CharToIdxMap[i])
			{
				handle->m_CharToIdxMap[i] = count++;
			}
		}
	}
	handle->m_usCharSetSize = count - 1;

	//build the idxtochar
	handle->m_IdxToCharMap = (char *)SRM_MALLOC(handle->m_usCharSetSize * sizeof(char));
	if (!handle->m_IdxToCharMap)
	{
		SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
		return;
	}
	memset(handle->m_IdxToCharMap, 0, handle->m_usCharSetSize * sizeof(char));
	for (i = 0; i < MAX_CHAR; i++)
	{
		int idx;
		idx = handle->m_CharToIdxMap[i];
		if (idx)
			handle->m_IdxToCharMap[idx - 1] = i;
	}

	//build the NowParseSet
	handle->m_NowParseSet = (char *)SRM_MALLOC(handle->m_usCharSetSize * sizeof(char));
	if (!handle->m_NowParseSet)
	{
		SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
		return;
	}
	memset(handle->m_NowParseSet, 0, handle->m_usCharSetSize * sizeof(char));
}

static INLINE int srm_nsearch(SRM_handle *handle, const char *matchstr, int begin, int end, int len, int flag)
{
	register int i;
	SRM_node_t *p_now;
	int idx;

	//last handle->m_usMinKeyWordSize-1 do not need to match
	end = end < len - handle->m_usMinKeyWordSize ? end : len - handle->m_usMinKeyWordSize;
	for (i = begin; i <= end; i++)
	{
		register int j;
		//对于每个字符都从路径头开始匹配
		p_now = handle->m_pTable;
		//我们匹配到不能匹配位置
		for (j = i; j < len; j++)
		{
			idx = SRM_CHARTOIDX(handle, matchstr[j]);
			if (idx < 0)
			{ //不在字符集中，我们过滤 or 不匹配
				if (flag & SRM_ILLEGAL_CHAR_JUMP)
					continue;
				else
					break;
			}
			p_now = SRM_GET_NEXTNODE(p_now, idx);
			if (!p_now)
			{ //not match
				break;
			}
			else
			{
				if (p_now->m_uiFlag & SRM_NODE_END)
				{
					if (((p_now->m_uiFlag & SRM_BEGINMATCH) && i != 0) || ((p_now->m_uiFlag & SRM_ENDMATCH) && j != len - 1))
						continue;
					return i;
				}
			}
		}
	}
	return -1;
}

static INLINE int srm_nmatch(SRM_handle *handle, const char *matchstr, int begin, int end, int len, int flag, unsigned int *presultsarray, unsigned int *pposarray, int maxresults, int *pallMatchSum)
{
	register int i;
	SRM_node_t *p_now;
	int idx;
	SRM_keyword_plink *p;
	SRM_keyword_t *pKeyWord;

	if (*pallMatchSum >= maxresults)
		return 0;
	//last handle->m_usMinKeyWordSize-1 do not need to match
	end = end < len - handle->m_usMinKeyWordSize ? end : len - handle->m_usMinKeyWordSize;
	for (i = begin; i <= end; i++)
	{
		register int j;

		//对于每个字符都从路径头开始匹配
		p_now = handle->m_pTable;
		//我们匹配到不能匹配位置
		for (j = i; j < len; j++)
		{
			idx = SRM_CHARTOIDX(handle, matchstr[j]);
			if (idx < 0)
			{ //不在字符集中，我们过滤 or 不匹配
				if (flag & SRM_ILLEGAL_CHAR_JUMP)
					continue;
				else
					break;
			}
			p_now = SRM_GET_NEXTNODE(p_now, idx);
			if (!p_now)
			{ //not match
				break;
			}
			else
			{
				if (p_now->m_uiFlag & SRM_NODE_END)
				{
					if (((p_now->m_uiFlag & SRM_BEGINMATCH) && i != 0) || ((p_now->m_uiFlag & SRM_ENDMATCH) && j != len - 1))
						continue;
					//some match
					p = p_now->m_pMatchKeyWordLink;
					while (p)
					{
						pKeyWord = p->m_pKeyWord;
						if (!(((p->m_uiFlag & SRM_BEGINMATCH) && i != 0) || ((p->m_uiFlag & SRM_ENDMATCH) && j != len - 1)))
						{
							if (*pallMatchSum < maxresults)
							{
								if (presultsarray)
									presultsarray[*pallMatchSum] = pKeyWord->m_uiValue;
								if (pposarray)
									pposarray[*pallMatchSum] = i;
#ifdef SRM_DEBUG_INFO
#ifdef SRM_DEBUG_MATCH_KEY_INFO
								{
									char tempStr[256] = "";
									SRM_PRINT("SRM match key:%s,str:%s\n", pKeyWord->m_pStr, strncpy(tempStr, matchstr + i, j - i + 1));
								}
#endif
#endif
								(*pallMatchSum)++;
							}
							if (*pallMatchSum >= maxresults)
								return 0;
						}
						p = p->m_pNext;
					}
				}
			}
		}
	}
	return 1;
}

static void srm_free_all(SRM_handle *handle)
{
	if (!handle)
		return;

	handle->m_iErrorCode = SRM_COMPILE_NOERROR;
	handle->m_iErrorPos = -1;
	handle->m_iErrorLine = -1;
	handle->m_iWarningCode = SRM_COMPILE_NOWARNING;
	handle->m_iWarningPos = -1;
	handle->m_iWarningLine = -1;

	srm_free_nodeplink(handle->m_pNowLink);
	handle->m_pNowLink = NULL;
	srm_free_nodeplink(handle->m_pNextLink);
	handle->m_pNextLink = NULL;

	//clear the match table
	srm_free_nodes(handle, handle->m_pTable);
	handle->m_pTable = NULL;

	//clear handle->m_pOpStack
	while (srm_pop_data(handle, &handle->m_pOpStack))
	{
	}

	//clear handle->m0ResStack
	{
		SRM_keyword_t *p;
		while ((p = (SRM_keyword_t *)srm_pop_data(handle, &handle->m_pResStack)))
		{
			srm_free_keywords(p);
		}
	}

	//clear keywordlist
	srm_free_keywords(handle->m_pKeyWordList);

	//clear the charset
	if (handle->m_CharToIdxMap)
		SRM_FREE(handle->m_CharToIdxMap);
	if (handle->m_IdxToCharMap)
		SRM_FREE(handle->m_IdxToCharMap);
	if (handle->m_NowParseSet)
		SRM_FREE(handle->m_NowParseSet);

	SRM_FREE(handle);
#ifdef SRM_DEBUG_INFO
#ifdef SRM_DEBUG_SHOW_MEMALLOC_INFO
	SRM_PRINT("SRM after srm_free_all:NewNum:%d,MaxNewNum:%d,AllNewNum:%d,NewSize:%d,AllNewSize:%d,AllNodes:%d\n", srm_g_NewNum, srm_g_MaxNewNum, srm_g_AllNewNum, srm_g_NewSize, srm_g_AllNewSize, srm_g_AllNodes);
#endif
#endif
}

int SRM_syntax(int flag)
{
	if (flag & SRM_SETFLAG_FLAG)
	{
		if (flag & SRM_USEDEFAULT_FLAG)
		{
			srm_g_NowFlag = srm_g_DefaultFlag;
		}
		else
		{
			srm_g_NowFlag = (flag & ~SRM_SETFLAG_FLAG);
		}
	}
	return srm_g_NowFlag;
}

void *SRM_compile(const char *regex, int flag, char *charset, int charnum)
{
	SRM_handle *handle;
	int len;
	if (!regex)
		return NULL;

	//initialize all
	len = sizeof(SRM_handle);
	handle = (SRM_handle *)SRM_MALLOC(sizeof(SRM_handle));
	if (!handle)
		return NULL;
	memset(handle, 0, sizeof(SRM_handle));

	//init handle
	handle->m_CharToIdxMap = NULL;
	handle->m_IdxToCharMap = NULL;
	handle->m_usCharSetSize = 0;
	handle->m_NowParseSet = NULL;

	handle->m_iFlag = srm_g_NowFlag;

	handle->m_pRegex = (char *)regex;
	handle->m_pToken = NULL;
	handle->m_pNowStr = NULL;

	handle->m_pTable = NULL;

	handle->m_bLastDollarChar = 0;
	handle->m_bLastCaretChar = 0;
	handle->m_bBeginMatch = 0;
	handle->m_bEndMatch = 0;

	handle->m_iErrorCode = SRM_COMPILE_NOERROR;
	handle->m_iErrorPos = -1;
	handle->m_iErrorLine = -1;
	handle->m_iWarningCode = SRM_COMPILE_NOWARNING;
	handle->m_iWarningPos = -1;
	handle->m_iWarningLine = -1;

	handle->m_pKeyWordList = NULL;
	handle->m_pNowKeyWord = NULL;
	handle->m_usNowKeyWordSize = 0;
	handle->m_usKeyWordStatFlag = 0;
	handle->m_usMinKeyWordSize = 65535;
	handle->m_usMaxEndMatchKeyWordSize = 0;

	handle->m_pResStack = NULL;
	handle->m_pOpStack = NULL;

	handle->m_pNextLink = NULL;
	handle->m_pNowLink = NULL;

	//set flag
	if (flag & SRM_SETFLAG_FLAG)
	{
		if (flag & SRM_USEDEFAULT_FLAG)
		{
			handle->m_iFlag = srm_g_DefaultFlag;
		}
		else
		{
			handle->m_iFlag = (flag & ~SRM_SETFLAG_FLAG);
		}
	}
	else
	{
		handle->m_iFlag = srm_g_NowFlag;
	}

	//build the char set map
	srm_build_charsetmap(handle, charset, charnum);
	if (handle->m_iErrorCode != SRM_COMPILE_NOERROR)
	{
#ifdef SRM_ERROR_INFO
		SRM_PRINT("SRM srm_build_charsetmap error!\n");
#endif
		goto ERROR_PROC;
	}
#ifdef SRM_DEBUG_INFO
#ifdef SRM_DEBUG_SHOW_MEMALLOC_INFO
	SRM_PRINT("SRM after srm_build_charsetmap:NewNum:%d,MaxNewNum:%d,AllNewNum:%d,NewSize:%d,AllNewSize:%d\n", srm_g_NewNum, srm_g_MaxNewNum, srm_g_AllNewNum, srm_g_NewSize, srm_g_AllNewSize);
#endif
#endif
	//parse the regex,and we get some keywords
	srm_parse_regex_to_keywords(handle);
	if (handle->m_iErrorCode != SRM_COMPILE_NOERROR)
	{
#ifdef SRM_ERROR_INFO
		SRM_PRINT("SRM srm_parse_regex_to_keywords error!\n");
#endif
		goto ERROR_PROC;
	}
	handle->m_pKeyWordList = (SRM_keyword_t *)srm_pop_data(handle, &handle->m_pResStack);
#ifdef SRM_DEBUG_INFO
#ifdef SRM_DEBUG_SHOW_MEMALLOC_INFO
	SRM_PRINT("SRM after srm_parse_regex_to_keywords:NewNum:%d,MaxNewNum:%d,AllNewNum:%d,NewSize:%d,AllNewSize:%d,AllNodes:%d\n", srm_g_NewNum, srm_g_MaxNewNum, srm_g_NewSize, srm_g_AllNewNum, srm_g_AllNewSize, srm_g_AllNodes);
#endif
#endif
	//create the start node
	handle->m_pTable = srm_node_copy(handle, NULL);
	if (!handle->m_pTable)
	{
		SRM_SETERROR(handle, SRM_COMPILE_MEM_ERROR);
#ifdef SRM_ERROR_INFO
		SRM_PRINT("SRM create table start node error!\n");
#endif
		goto ERROR_PROC;
	}
	//parse every keyword
	{
		SRM_keyword_t *p = handle->m_pKeyWordList;
		while (p)
		{
#ifdef SRM_DEBUG_INFO
#ifdef SRM_DEBUG_SHOW_ALLKEYWORDS_INFO
			SRM_PRINT("SRM %s(%d %d)\n", p->m_pStr, p->m_iStrLen, p->m_iStrBufLen);
#endif
#endif
			if (p->m_iStrLen < MAX_KEYWORDSIZE)
			{

				handle->m_pNowKeyWord = p;

				//clear the error and warning code
				handle->m_iErrorCode = SRM_COMPILE_NOERROR;
				handle->m_iErrorPos = -1;
				handle->m_iErrorLine = -1;
				handle->m_iWarningCode = SRM_COMPILE_NOWARNING;
				handle->m_iWarningPos = -1;
				handle->m_iWarningLine = -1;

				srm_parse_keyword(handle);
				if (handle->m_iErrorCode != SRM_COMPILE_NOERROR)
				{
#ifdef SRM_ERROR_INFO
					SRM_PRINT("SRM keyword:%s error:0x%x,errorpos:%d,errorline:%d\n", p->m_pStr, handle->m_iErrorCode, handle->m_iErrorPos, handle->m_iErrorLine);
					SRM_PRINT("SRM keyword:%s warning:0x%x,warningpos:%d,warningline:%d\n", p->m_pStr, handle->m_iWarningCode, handle->m_iWarningPos, handle->m_iWarningLine);
#endif
					//fatal error,we stop the parse procedure
					if (handle->m_iErrorCode == SRM_COMPILE_MEM_ERROR || handle->m_iErrorCode == SRM_COMPILE_REFCOUNT_ERROR)
						goto ERROR_PROC;
				}
			}
			else
			{
#ifdef SRM_ERROR_INFO
				SRM_PRINT("SRM Keyword(%s) size is larger than %d!\n", p->m_pStr, MAX_KEYWORDSIZE);
#endif
			}
			p = p->m_pNext;
		}
	}

#ifdef SRM_DEBUG_INFO
#ifdef SRM_DEBUG_SHOW_MEMALLOC_INFO
	SRM_PRINT("SRM after srm_parsekeywords:NewNum:%d,MaxNewNum:%d,AllNewNum:%d,NewSize:%d,AllNewSize:%d,AllNodes:%d\n", srm_g_NewNum, srm_g_MaxNewNum, srm_g_AllNewNum, srm_g_NewSize, srm_g_AllNewSize, srm_g_AllNodes);
#endif
#endif
	//ok,parse succeed
	return handle;
ERROR_PROC:
	//compile error, we need free all the memory that has malloced
#ifdef SRM_ERROR_INFO
	SRM_PRINT("SRM fatal error,compile stop!\n");
	srm_show_errors(handle);
	//SRM_PRINT("SRM error:0x%x,errorpos:%d,errorline:%d\n",handle->m_iErrorCode,handle->m_iErrorPos,handle->m_iErrorLine);
	//SRM_PRINT("SRM warning:0x%x,warningpos:%d,warningline:%d\n",handle->m_iWarningCode,handle->m_iWarningPos,handle->m_iWarningLine);
#endif
	srm_free_all(handle);
	handle = NULL;
	return NULL;
}

int SRM_search(void *srmhandle, const char *matchstr)
{
	SRM_handle *handle;
	size_t len;
	int flag, res, begin, end;

	handle = (SRM_handle *)srmhandle;
	if (!handle || !handle->m_pTable || !matchstr)
		return -2;

	len = strlen(matchstr);
	flag = handle->m_iFlag;
	res = -1;
	begin = 0;
	end = len - 1;

	if (handle->m_usKeyWordStatFlag & SRM_BEGINMATCH_STATFLAG)
	{
		res = srm_nsearch(handle, matchstr, 0, 0, len, flag);
		if (res >= 0)
			return res;
		begin = 1;
	}
	if (handle->m_usKeyWordStatFlag & SRM_ENDMATCH_STATFLAG)
	{
		end = (int)len > begin + handle->m_usMaxEndMatchKeyWordSize ? len - handle->m_usMaxEndMatchKeyWordSize : begin;
		res = srm_nsearch(handle, matchstr, end, len - 1, len, flag);
		if (res >= 0)
			return res;
		end = end - 1;
	}
	if (handle->m_usKeyWordStatFlag & SRM_OTHERMATCH_STATFLAG)
	{
		res = srm_nsearch(handle, matchstr, begin, end, len, flag);
		if (res >= 0)
			return res;
	}
	return res;
}

int SRM_match_ex(void *srmhandle, const char *matchstr, unsigned int *presultsarray, unsigned int *pposarray, int maxresults)
{
	SRM_handle *handle;
	size_t len;
	int flag, res, begin, end;
	int allMatchSum;

	handle = (SRM_handle *)srmhandle;
	if (!handle || !handle->m_pTable || !matchstr)
		return -2;

	len = strlen(matchstr);
	flag = handle->m_iFlag;
	allMatchSum = 0;
	res = -1;
	begin = 0;
	end = len - 1;

	if (handle->m_usKeyWordStatFlag & SRM_OTHERMATCH_STATFLAG)
	{
		srm_nmatch(handle, matchstr, begin, end, len, flag, presultsarray, pposarray, maxresults, &allMatchSum);
		return allMatchSum;
	}
	else
	{
		if (handle->m_usKeyWordStatFlag & SRM_BEGINMATCH_STATFLAG)
		{
			res = srm_nmatch(handle, matchstr, 0, 0, len, flag, presultsarray, pposarray, maxresults, &allMatchSum);
			if (res == 0)
				return allMatchSum;
			begin = 1;
		}
		if (handle->m_usKeyWordStatFlag & SRM_ENDMATCH_STATFLAG)
		{
			begin = (int)len > begin + handle->m_usMaxEndMatchKeyWordSize ? len - handle->m_usMaxEndMatchKeyWordSize : begin;
			srm_nmatch(handle, matchstr, begin, end, len, flag, presultsarray, pposarray, maxresults, &allMatchSum);
			return allMatchSum;
		}
	}
	return allMatchSum;
}

int SRM_match(void *srmhandle, const char *matchstr, unsigned int *presultsarray, int maxresults)
{
	return SRM_match_ex(srmhandle, matchstr, presultsarray, NULL, maxresults);
}

void SRM_free(void *srmHandle)
{
	srm_free_all((SRM_handle *)srmHandle);
}
