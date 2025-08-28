#pragma once

#include <string>

namespace dns 
{

// #define	A       1   /* IPv4 address */
// #define	NS      2   /* Authoritative name server */
// #define	CNAME   5   /* Canonical name for an alias */
// #define	MX      15  /* Mail exchange */
// #define SOA     6   /* Start Of a zone of Authority */
// #define	TXT     16  /* Text strings */
// #define PTR		12

typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;

	
// typedef struct {
// 	unsigned short id; // identification number
	
// 	unsigned char rd :1; // recursion desired
// 	unsigned char tc :1; // truncated message
// 	unsigned char aa :1; // authoritive answer
// 	unsigned char opcode :4; // purpose of message
// 	unsigned char qr :1; // query/response flag: 0=query; 1=response
	
// 	unsigned char rcode :4;
// 	unsigned char z :3;
// 	unsigned char ra :1;
	
// 	unsigned short qdcount;
// 	unsigned short ancount;
// 	unsigned short nscount;
// 	unsigned short arcount;
// } dns_header_t;


class Message 
{
public:

    enum Type { Query=0, Response };


    virtual int code(char* buffer) = 0;
    virtual void decode(const char* buffer, int size) = 0;

    uint getID() const { return m_id; }
    uint getQdCount() const { return m_qdCount; }
    uint getAnCount() const { return m_anCount; }
    uint getNsCount() const { return m_nsCount; }
    uint getArCount() const { return m_arCount; }

    void setID(uint id) { m_id = id; }
    void setQdCount(uint count) { m_qdCount = count; }
    void setAnCount(uint count) { m_anCount = count; }
    void setNsCount(uint count) { m_nsCount = count; }
    void setArCount(uint count) { m_arCount = count; }

protected:
    Message(Type type);
    ~Message();

    static const uint HDR_OFFSET = 12;

    uint m_id;
    uint m_qr;          // query/response flag: 0=query; 1=response
    uint m_opcode;      // purpose of message
    uint m_aa;          // authoritive answer
    uint m_tc;          // truncated message
    uint m_rd;          // recursion desired
    uint m_ra;

    uint m_rcode;
    
    uint m_qdCount;
    uint m_anCount;
    uint m_nsCount;
    uint m_arCount;

    virtual std::string asString() const ;

    void decode_hdr(const char* buffer) ;
    void code_hdr(char* buffer) ;

    int get16bits(const char*& buffer) ;
    int get32bits(const char*& buffer) ;

    void put16bits(char*& buffer, uint value) ;
    void put32bits(char*& buffer, ulong value) ;

    void log_buffer(const char* buffer, int size) ;
    
private:
    static const uint QR_MASK = 0x8000;
    static const uint OPCODE_MASK = 0x7800;
    static const uint AA_MASK = 0x0400;
    static const uint TC_MASK = 0x0200;
    static const uint RD_MASK = 0x0100;
    static const uint RA_MASK = 0x0080;
    static const uint RCODE_MASK = 0x000F;
};

}


