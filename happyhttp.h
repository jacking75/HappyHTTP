/*
 2018. 12. 27
 Choi HeungBae 
 Change 1 header file
*/
/*
 * HappyHTTP - a simple HTTP library
 * Version 0.1
 * 
 * Copyright (c) 2006 Ben Campbell
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.
 * 
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 * claim that you wrote the original software. If you use this software in a
 * product, an acknowledgment in the product documentation would be
 * appreciated but is not required.
 *
 * 2. Altered source versions must be plainly marked as such, and must not
 * be misrepresented as being the original software.
 * 
 * 3. This notice may not be removed or altered from any source distribution.
 *
 */


#ifndef HAPPYHTTP_H
#define HAPPYHTTP_H


#include <string>
#include <map>
#include <vector>
#include <deque>

#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#define _CRT_SECURE_NO_WARNINGS 1

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>	// for gethostbyname()
#include <errno.h>
#include <unistd.h>
#include <arpa/net.h>
#else
#include <WinSock2.h>
#include <ws2tcpip.h>
#define vsnprintf _vsnprintf
#endif

#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <assert.h>

#include <string>
#include <vector>
#include <algorithm>

#ifndef _WIN32
#define _stricmp strcasecmp
#endif


// forward decl
struct in_addr;

namespace happyhttp
{
	using namespace std;

class Response;

// Helper Functions
void BailOnSocketError(const char* context)
{
#ifdef _WIN32

	int e = WSAGetLastError();
	const char* msg = GetWinsockErrorString(e);
#else
	const char* msg = strerror(errno);
#endif
	throw Wobbly("%s: %s", context, msg);
}

#ifdef _WIN32

const char* GetWinsockErrorString(int err)
{
	switch (err)
	{
	case 0:					return "No error";
	case WSAEINTR:			return "Interrupted system call";
	case WSAEBADF:			return "Bad file number";
	case WSAEACCES:			return "Permission denied";
	case WSAEFAULT:			return "Bad address";
	case WSAEINVAL:			return "Invalid argument";
	case WSAEMFILE:			return "Too many open sockets";
	case WSAEWOULDBLOCK:	return "Operation would block";
	case WSAEINPROGRESS:	return "Operation now in progress";
	case WSAEALREADY:		return "Operation already in progress";
	case WSAENOTSOCK:		return "Socket operation on non-socket";
	case WSAEDESTADDRREQ:	return "Destination address required";
	case WSAEMSGSIZE:		return "Message too long";
	case WSAEPROTOTYPE:		return "Protocol wrong type for socket";
	case WSAENOPROTOOPT:	return "Bad protocol option";
	case WSAEPROTONOSUPPORT:	return "Protocol not supported";
	case WSAESOCKTNOSUPPORT:	return "Socket type not supported";
	case WSAEOPNOTSUPP:		return "Operation not supported on socket";
	case WSAEPFNOSUPPORT:	return "Protocol family not supported";
	case WSAEAFNOSUPPORT:	return "Address family not supported";
	case WSAEADDRINUSE:		return "Address already in use";
	case WSAEADDRNOTAVAIL:	return "Can't assign requested address";
	case WSAENETDOWN:		return "Network is down";
	case WSAENETUNREACH:	return "Network is unreachable";
	case WSAENETRESET:		return "Net connection reset";
	case WSAECONNABORTED:	return "Software caused connection abort";
	case WSAECONNRESET:		return "Connection reset by peer";
	case WSAENOBUFS:		return "No buffer space available";
	case WSAEISCONN:		return "Socket is already connected";
	case WSAENOTCONN:		return "Socket is not connected";
	case WSAESHUTDOWN:		return "Can't send after socket shutdown";
	case WSAETOOMANYREFS:	return "Too many references, can't splice";
	case WSAETIMEDOUT:		return "Connection timed out";
	case WSAECONNREFUSED:	return "Connection refused";
	case WSAELOOP:			return "Too many levels of symbolic links";
	case WSAENAMETOOLONG:	return "File name too long";
	case WSAEHOSTDOWN:		return "Host is down";
	case WSAEHOSTUNREACH:	return "No route to host";
	case WSAENOTEMPTY:		return "Directory not empty";
	case WSAEPROCLIM:		return "Too many processes";
	case WSAEUSERS:			return "Too many users";
	case WSAEDQUOT:			return "Disc quota exceeded";
	case WSAESTALE:			return "Stale NFS file handle";
	case WSAEREMOTE:		return "Too many levels of remote in path";
	case WSASYSNOTREADY:	return "Network system is unavailable";
	case WSAVERNOTSUPPORTED:	return "Winsock version out of range";
	case WSANOTINITIALISED:	return "WSAStartup not yet called";
	case WSAEDISCON:		return "Graceful shutdown in progress";
	case WSAHOST_NOT_FOUND:	return "Host not found";
	case WSANO_DATA:		return "No host data of that type was found";
	}

	return "unknown";
};
#endif // _WIN32

// return true if socket has data waiting to be read
bool datawaiting(int sock)
{
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(sock, &fds);

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 0;

	int r = select(sock + 1, &fds, NULL, NULL, &tv);
	if (r < 0)
		BailOnSocketError("select");

	if (FD_ISSET(sock, &fds))
		return true;
	else
		return false;
}

// Try to work out address from string
// returns 0 if bad
struct in_addr *atoaddr(const char* address)
{
	struct hostent *host;
	static struct in_addr saddr;

	// First try nnn.nnn.nnn.nnn form
	saddr.s_addr = inet_addr(address);
	if (saddr.s_addr != INADDR_NONE)
		return &saddr;

	host = gethostbyname(address);
	if (host)
		return (struct in_addr *) *host->h_addr_list;

	return 0;
}


typedef void (*ResponseBegin_CB)( const Response* r, void* userdata );
typedef void (*ResponseData_CB)( const Response* r, void* userdata, const unsigned char* data, int numbytes );
typedef void (*ResponseComplete_CB)( const Response* r, void* userdata );


// HTTP status codes
enum {
	// 1xx informational
	CONTINUE = 100,
	SWITCHING_PROTOCOLS = 101,
	PROCESSING = 102,

	// 2xx successful
	OK = 200,
	CREATED = 201,
	ACCEPTED = 202,
	NON_AUTHORITATIVE_INFORMATION = 203,
	NO_CONTENT = 204,
	RESET_CONTENT = 205,
	PARTIAL_CONTENT = 206,
	MULTI_STATUS = 207,
	IM_USED = 226,

	// 3xx redirection
	MULTIPLE_CHOICES = 300,
	MOVED_PERMANENTLY = 301,
	FOUND = 302,
	SEE_OTHER = 303,
	NOT_MODIFIED = 304,
	USE_PROXY = 305,
	TEMPORARY_REDIRECT = 307,
	
	// 4xx client error
	BAD_REQUEST = 400,
	UNAUTHORIZED = 401,
	PAYMENT_REQUIRED = 402,
	FORBIDDEN = 403,
	NOT_FOUND = 404,
	METHOD_NOT_ALLOWED = 405,
	NOT_ACCEPTABLE = 406,
	PROXY_AUTHENTICATION_REQUIRED = 407,
	REQUEST_TIMEOUT = 408,
	CONFLICT = 409,
	GONE = 410,
	LENGTH_REQUIRED = 411,
	PRECONDITION_FAILED = 412,
	REQUEST_ENTITY_TOO_LARGE = 413,
	REQUEST_URI_TOO_LONG = 414,
	UNSUPPORTED_MEDIA_TYPE = 415,
	REQUESTED_RANGE_NOT_SATISFIABLE = 416,
	EXPECTATION_FAILED = 417,
	UNPROCESSABLE_ENTITY = 422,
	LOCKED = 423,
	FAILED_DEPENDENCY = 424,
	UPGRADE_REQUIRED = 426,

	// 5xx server error
	INTERNAL_SERVER_ERROR = 500,
	NOT_IMPLEMENTED = 501,
	BAD_GATEWAY = 502,
	SERVICE_UNAVAILABLE = 503,
	GATEWAY_TIMEOUT = 504,
	HTTP_VERSION_NOT_SUPPORTED = 505,
	INSUFFICIENT_STORAGE = 507,
	NOT_EXTENDED = 510,
};



// Exception class
class Wobbly
{
public:
	Wobbly(const char* fmt, ...)
	{
		va_list ap;
		va_start(ap, fmt);
		int n = vsnprintf(m_Message, MAXLEN, fmt, ap);
		va_end(ap);
		if (n == MAXLEN)
			m_Message[MAXLEN - 1] = '\0';
	}

	const char* what() const
		{ return m_Message; }
protected:
	enum { MAXLEN=256 };
	char m_Message[ MAXLEN ];
};



//-------------------------------------------------
// Connection
//
// Handles the socket connection, issuing of requests and managing
// responses.
// ------------------------------------------------

class Connection
{
	friend class Response;
public:
	// doesn't connect immediately
	Connection(const char* host, int port) :
		m_ResponseBeginCB(0),
		m_ResponseDataCB(0),
		m_ResponseCompleteCB(0),
		m_UserData(0),
		m_State(IDLE),
		m_Host(host),
		m_Port(port),
		m_Sock(-1)
	{
	}

	~Connection()
	{
		close();
	}

	// Set up the response handling callbacks. These will be invoked during
	// calls to pump().
	// begincb		- called when the responses headers have been received
	// datacb		- called repeatedly to handle body data
	// completecb	- response is completed
	// userdata is passed as a param to all callbacks.
	void setcallbacks(
		ResponseBegin_CB begincb,
		ResponseData_CB datacb,
		ResponseComplete_CB completecb,
		void* userdata )
	{
		m_ResponseBeginCB = begincb;
		m_ResponseDataCB = datacb;
		m_ResponseCompleteCB = completecb;
		m_UserData = userdata;
	}

	// Don't need to call connect() explicitly as issuing a request will
	// call it automatically if needed.
	// But it could block (for name lookup etc), so you might prefer to
	// call it in advance.
	void connect()
	{
		in_addr* addr = atoaddr(m_Host.c_str());
		if (!addr)
			throw Wobbly("Invalid network address");

		sockaddr_in address;
		memset((char*)&address, 0, sizeof(address));
		address.sin_family = AF_INET;
		address.sin_port = htons(m_Port);
		address.sin_addr.s_addr = addr->s_addr;

		m_Sock = socket(AF_INET, SOCK_STREAM, 0);
		if (m_Sock < 0)
			BailOnSocketError("socket()");

		//	printf("Connecting to %s on port %d.\n",inet_ntoa(*addr), port);

		if (::connect(m_Sock, (sockaddr const*)&address, sizeof(address)) < 0)
			BailOnSocketError("connect()");
	}

	// close connection, discarding any pending requests.
	void close()
	{
#ifdef _WIN32
		if (m_Sock >= 0)
			::closesocket(m_Sock);
#else
		if (m_Sock >= 0)
			::close(m_Sock);
#endif
		m_Sock = -1;

		// discard any incomplete responses
		while (!m_Outstanding.empty())
		{
			delete m_Outstanding.front();
			m_Outstanding.pop_front();
		}
	}


	// Update the connection (non-blocking)
	// Just keep calling this regularly to service outstanding requests.
	void pump()
	{
		if (m_Outstanding.empty())
			return;		// no requests outstanding

		assert(m_Sock > 0);	// outstanding requests but no connection!

		if (!datawaiting(m_Sock))
			return;				// recv will block

		unsigned char buf[2048];
		int a = recv(m_Sock, (char*)buf, sizeof(buf), 0);
		if (a < 0)
			BailOnSocketError("recv()");

		if (a == 0)
		{
			// connection has closed

			Response* r = m_Outstanding.front();
			r->notifyconnectionclosed();
			assert(r->completed());
			delete r;
			m_Outstanding.pop_front();

			// any outstanding requests will be discarded
			close();
		}
		else
		{
			int used = 0;
			while (used < a && !m_Outstanding.empty())
			{

				Response* r = m_Outstanding.front();
				int u = r->pump(&buf[used], a - used);

				// delete response once completed
				if (r->completed())
				{
					delete r;
					m_Outstanding.pop_front();
				}
				used += u;
			}

			// NOTE: will lose bytes if response queue goes empty
			// (but server shouldn't be sending anything if we don't have
			// anything outstanding anyway)
			assert(used == a);	// all bytes should be used up by here.
		}
	}

	// any requests still outstanding?
	bool outstanding() const
		{ return !m_Outstanding.empty(); }

	// ---------------------------
	// high-level request interface
	// ---------------------------
	
	// method is "GET", "POST" etc...
	// url is only path part: eg  "/index.html"
	// headers is array of name/value pairs, terminated by a null-ptr
	// body & bodysize specify body data of request (eg values for a form)
	void request( const char* method, const char* url, const char* headers[]=0,
		const unsigned char* body=0, int bodysize=0 )
	{

		bool gotcontentlength = false;	// already in headers?

		// check headers for content-length
		// TODO: check for "Host" and "Accept-Encoding" too
		// and avoid adding them ourselves in putrequest()
		if (headers)
		{
			const char** h = headers;
			while (*h)
			{
				const char* name = *h++;
#ifndef NDEBUG
				const char* value = *h++;
#endif
				assert(value != 0);	// name with no value!

				if (0 == _stricmp(name, "content-length"))
					gotcontentlength = true;
			}
		}

		putrequest(method, url);

		if (body && !gotcontentlength)
			putheader("Content-Length", bodysize);

		if (headers)
		{
			const char** h = headers;
			while (*h)
			{
				const char* name = *h++;
				const char* value = *h++;
				putheader(name, value);
			}
		}
		endheaders();

		if (body)
			send(body, bodysize);

	}

	// ---------------------------
	// low-level request interface
	// ---------------------------

	// begin request
	// method is "GET", "POST" etc...
	// url is only path part: eg  "/index.html"
	void putrequest( const char* method, const char* url )
	{
		if (m_State != IDLE)
			throw Wobbly("Request already issued");

		m_State = REQ_STARTED;

		std::string req = method;
		req.append(" ");
		req.append(url);
		req.append(" HTTP/1.1");
		m_Buffer.push_back(req);

		putheader("Host", m_Host.c_str());	// required for HTTP1.1

		// don't want any fancy encodings please
		putheader("Accept-Encoding", "identity");

		// Push a new response onto the queue
		Response *r = new Response(method, *this);
		m_Outstanding.push_back(r);
	}


	// Add a header to the request (call after putrequest() )
	void putheader( const char* header, const char* value )
	{
		if (m_State != REQ_STARTED)
			throw Wobbly("putheader() failed");
		m_Buffer.push_back(string(header) + ": " + string(value));
	}

	void putheader( const char* header, int numericvalue )	// alternate version
	{
		char buf[32];
		sprintf(buf, "%d", numericvalue);
		putheader(header, buf);
	}

	// Finished adding headers, issue the request.
	void endheaders()
	{
		if (m_State != REQ_STARTED)
			throw Wobbly("Cannot send header");
		m_State = IDLE;

		m_Buffer.push_back("");

		string msg;
		vector< string>::const_iterator it;
		for (it = m_Buffer.begin(); it != m_Buffer.end(); ++it)
			msg += (*it) + "\r\n";

		m_Buffer.clear();

		//	printf( "%s", msg.c_str() );
		send((const unsigned char*)msg.c_str(), msg.size());
	}

	// send body data if any.
	// To be called after endheaders()
	void send( const unsigned char* buf, int numbytes )
	{
		//	fwrite( buf, 1,numbytes, stdout );

		if (m_Sock < 0)
			connect();

		while (numbytes > 0)
		{
#ifdef _WIN32
			int n = ::send(m_Sock, (const char*)buf, numbytes, 0);
#else
			int n = ::send(m_Sock, buf, numbytes, 0);
#endif
			if (n < 0)
				BailOnSocketError("send()");
			numbytes -= n;
			buf += n;
		}
	}

protected:
	// some bits of implementation exposed to Response class

	// callbacks
	ResponseBegin_CB	m_ResponseBeginCB;
	ResponseData_CB		m_ResponseDataCB;
	ResponseComplete_CB	m_ResponseCompleteCB;
	void*				m_UserData;

private:
	enum { IDLE, REQ_STARTED, REQ_SENT } m_State;
	std::string m_Host;
	int m_Port;
	int m_Sock;
	std::vector< std::string > m_Buffer;	// lines of request

	std::deque< Response* > m_Outstanding;	// responses for outstanding requests
};






//-------------------------------------------------
// Response
//
// Handles parsing of response data.
// ------------------------------------------------


class Response
{
	friend class Connection;
public:

	// retrieve a header (returns 0 if not present)
	const char* getheader( const char* name ) const
	{
		std::string lname(name);
#ifdef _MSC_VER
		std::transform(lname.begin(), lname.end(), lname.begin(), tolower);
#else
		std::transform(lname.begin(), lname.end(), lname.begin(), ::tolower);
#endif

		std::map< std::string, std::string >::const_iterator it = m_Headers.find(lname);
		if (it == m_Headers.end())
			return 0;
		else
			return it->second.c_str();
	}


	bool completed() const
		{ return m_State == COMPLETE; }


	// get the HTTP status code
	int getstatus() const
	{
		// only valid once we've got the statusline
		assert(m_State != STATUSLINE);
		return m_Status;
	}

	// get the HTTP response reason string
	const char* getreason() const
	{
		// only valid once we've got the statusline
		assert(m_State != STATUSLINE);
		return m_Reason.c_str();
	}

	// true if connection is expected to close after this response.
	bool willclose() const
		{ return m_WillClose; }
protected:
	// interface used by Connection

	// only Connection creates Responses.
	Response(const char* method, Connection& conn) :
		m_State(STATUSLINE),
		m_Connection(conn),
		m_Method(method),
		m_Version(0),
		m_Status(0),
		m_BytesRead(0),
		m_Chunked(false),
		m_ChunkLeft(0),
		m_Length(-1),
		m_WillClose(false)
	{
	}


	// pump some data in for processing.
	// Returns the number of bytes used.
	// Will always return 0 when response is complete.
	int pump( const unsigned char* data, int datasize )
	{
		assert(datasize != 0);
		int count = datasize;

		while (count > 0 && m_State != COMPLETE)
		{
			if (m_State == STATUSLINE ||
				m_State == HEADERS ||
				m_State == TRAILERS ||
				m_State == CHUNKLEN ||
				m_State == CHUNKEND)
			{
				// we want to accumulate a line
				while (count > 0)
				{
					char c = (char)*data++;
					--count;
					if (c == '\n')
					{
						// now got a whole line!
						switch (m_State)
						{
						case STATUSLINE:
							ProcessStatusLine(m_LineBuf);
							break;
						case HEADERS:
							ProcessHeaderLine(m_LineBuf);
							break;
						case TRAILERS:
							ProcessTrailerLine(m_LineBuf);
							break;
						case CHUNKLEN:
							ProcessChunkLenLine(m_LineBuf);
							break;
						case CHUNKEND:
							// just soak up the crlf after body and go to next state
							assert(m_Chunked == true);
							m_State = CHUNKLEN;
							break;
						default:
							break;
						}
						m_LineBuf.clear();
						break;		// break out of line accumulation!
					}
					else
					{
						if (c != '\r')		// just ignore CR
							m_LineBuf += c;
					}
				}
			}
			else if (m_State == BODY)
			{
				int bytesused = 0;
				if (m_Chunked)
					bytesused = ProcessDataChunked(data, count);
				else
					bytesused = ProcessDataNonChunked(data, count);
				data += bytesused;
				count -= bytesused;
			}
		}

		// return number of bytes used
		return datasize - count;
	}

	// tell response that connection has closed
	void notifyconnectionclosed()
	{
		if (m_State == COMPLETE)
			return;

		// eof can be valid...
		if (m_State == BODY &&
			!m_Chunked &&
			m_Length == -1)
		{
			Finish();	// we're all done!
		}
		else
		{
			throw Wobbly("Connection closed unexpectedly");
		}
	}

private:
	enum {
		STATUSLINE,		// start here. status line is first line of response.
		HEADERS,		// reading in header lines
		BODY,			// waiting for some body data (all or a chunk)
		CHUNKLEN,		// expecting a chunk length indicator (in hex)
		CHUNKEND,		// got the chunk, now expecting a trailing blank line
		TRAILERS,		// reading trailers after body.
		COMPLETE,		// response is complete!
	} m_State;

	Connection& m_Connection;	// to access callback ptrs
	std::string m_Method;		// req method: "GET", "POST" etc...

	// status line
	std::string	m_VersionString;	// HTTP-Version
	int	m_Version;			// 10: HTTP/1.0    11: HTTP/1.x (where x>=1)
	int m_Status;			// Status-Code
	std::string m_Reason;	// Reason-Phrase

	// header/value pairs
	std::map<std::string,std::string> m_Headers;

	int		m_BytesRead;		// body bytes read so far
	bool	m_Chunked;			// response is chunked?
	int		m_ChunkLeft;		// bytes left in current chunk
	int		m_Length;			// -1 if unknown
	bool	m_WillClose;		// connection will close at response end?

	std::string m_LineBuf;		// line accumulation for states that want it
	std::string m_HeaderAccum;	// accumulation buffer for headers


	// process accumulated header data
	void FlushHeader()
	{
		if (m_HeaderAccum.empty())
			return;	// no flushing required

		const char* p = m_HeaderAccum.c_str();

		std::string header;
		std::string value;
		while (*p && *p != ':')
			header += tolower(*p++);

		// skip ':'
		if (*p)
			++p;

		// skip space
		while (*p && (*p == ' ' || *p == '\t'))
			++p;

		value = p; // rest of line is value

		m_Headers[header] = value;
		//	printf("header: ['%s': '%s']\n", header.c_str(), value.c_str() );	

		m_HeaderAccum.clear();
	}

	void ProcessStatusLine( std::string const& line )
	{
		const char* p = line.c_str();

		// skip any leading space
		while (*p && *p == ' ')
			++p;

		// get version
		while (*p && *p != ' ')
			m_VersionString += *p++;
		while (*p && *p == ' ')
			++p;

		// get status code
		std::string status;
		while (*p && *p != ' ')
			status += *p++;
		while (*p && *p == ' ')
			++p;

		// rest of line is reason
		while (*p)
			m_Reason += *p++;

		m_Status = atoi(status.c_str());
		if (m_Status < 100 || m_Status > 999)
			throw Wobbly("BadStatusLine (%s)", line.c_str());

		/*
			printf( "version: '%s'\n", m_VersionString.c_str() );
			printf( "status: '%d'\n", m_Status );
			printf( "reason: '%s'\n", m_Reason.c_str() );
		*/

		if (m_VersionString == "HTTP:/1.0")
			m_Version = 10;
		else if (0 == m_VersionString.compare(0, 7, "HTTP/1."))
			m_Version = 11;
		else
			throw Wobbly("UnknownProtocol (%s)", m_VersionString.c_str());
		// TODO: support for HTTP/0.9


		// OK, now we expect headers!
		m_State = HEADERS;
		m_HeaderAccum.clear();
	}

	void ProcessHeaderLine( std::string const& line )
	{
		const char* p = line.c_str();
		if (line.empty())
		{
			FlushHeader();
			// end of headers

			// HTTP code 100 handling (we ignore 'em)
			if (m_Status == CONTINUE)
				m_State = STATUSLINE;	// reset parsing, expect new status line
			else
				BeginBody();			// start on body now!
			return;
		}

		if (isspace(*p))
		{
			// it's a continuation line - just add it to previous data
			++p;
			while (*p && isspace(*p))
				++p;

			m_HeaderAccum += ' ';
			m_HeaderAccum += p;
		}
		else
		{
			// begin a new header
			FlushHeader();
			m_HeaderAccum = p;
		}
	}

	void ProcessTrailerLine( std::string const& line )
	{
		// TODO: handle trailers?
		// (python httplib doesn't seem to!)
		if (line.empty())
			Finish();

		// just ignore all the trailers...
	}

	void ProcessChunkLenLine( std::string const& line )
	{
		// chunklen in hex at beginning of line
		m_ChunkLeft = strtol(line.c_str(), NULL, 16);

		if (m_ChunkLeft == 0)
		{
			// got the whole body, now check for trailing headers
			m_State = TRAILERS;
			m_HeaderAccum.clear();
		}
		else
		{
			m_State = BODY;
		}
	}

	// handle some body data in chunked mode
	// returns number of bytes used.
	int ProcessDataChunked( const unsigned char* data, int count )
	{
		assert(m_Chunked);

		int n = count;
		if (n > m_ChunkLeft)
			n = m_ChunkLeft;

		// invoke callback to pass out the data
		if (m_Connection.m_ResponseDataCB)
			(m_Connection.m_ResponseDataCB)(this, m_Connection.m_UserData, data, n);

		m_BytesRead += n;

		m_ChunkLeft -= n;
		assert(m_ChunkLeft >= 0);
		if (m_ChunkLeft == 0)
		{
			// chunk completed! now soak up the trailing CRLF before next chunk
			m_State = CHUNKEND;
		}
		return n;
	}
	
	// handle some body data in non-chunked mode.
	// returns number of bytes used.
	int ProcessDataNonChunked( const unsigned char* data, int count )
	{
		int n = count;
		if (m_Length != -1)
		{
			// we know how many bytes to expect
			int remaining = m_Length - m_BytesRead;
			if (n > remaining)
				n = remaining;
		}

		// invoke callback to pass out the data
		if (m_Connection.m_ResponseDataCB)
			(m_Connection.m_ResponseDataCB)(this, m_Connection.m_UserData, data, n);

		m_BytesRead += n;

		// Finish if we know we're done. Else we're waiting for connection close.
		if (m_Length != -1 && m_BytesRead == m_Length)
			Finish();

		return n;
	}

	// OK, we've now got all the headers read in, so we're ready to start
	// on the body. But we need to see what info we can glean from the headers
	// first...
	void BeginBody()
	{

		m_Chunked = false;
		m_Length = -1;	// unknown
		m_WillClose = false;

		// using chunked encoding?
		const char* trenc = getheader("transfer-encoding");
		if (trenc && 0 == _stricmp(trenc, "chunked"))
		{
			m_Chunked = true;
			m_ChunkLeft = -1;	// unknown
		}

		m_WillClose = CheckClose();

		// length supplied?
		const char* contentlen = getheader("content-length");
		if (contentlen && !m_Chunked)
		{
			m_Length = atoi(contentlen);
		}

		// check for various cases where we expect zero-length body
		if (m_Status == NO_CONTENT ||
			m_Status == NOT_MODIFIED ||
			(m_Status >= 100 && m_Status < 200) ||		// 1xx codes have no body
			m_Method == "HEAD")
		{
			m_Length = 0;
		}


		// if we're not using chunked mode, and no length has been specified,
		// assume connection will close at end.
		if (!m_WillClose && !m_Chunked && m_Length == -1)
			m_WillClose = true;



		// Invoke the user callback, if any
		if (m_Connection.m_ResponseBeginCB)
			(m_Connection.m_ResponseBeginCB)(this, m_Connection.m_UserData);

		/*
			printf("---------BeginBody()--------\n");
			printf("Length: %d\n", m_Length );
			printf("WillClose: %d\n", (int)m_WillClose );
			printf("Chunked: %d\n", (int)m_Chunked );
			printf("ChunkLeft: %d\n", (int)m_ChunkLeft );
			printf("----------------------------\n");
		*/
		// now start reading body data!
		if (m_Chunked)
			m_State = CHUNKLEN;
		else
			m_State = BODY;
	}

	// return true if we think server will automatically close connection
	bool CheckClose()
	{
		if (m_Version == 11)
		{
			// HTTP1.1
			// the connection stays open unless "connection: close" is specified.
			const char* conn = getheader("connection");
			if (conn && 0 == _stricmp(conn, "close"))
				return true;
			else
				return false;
		}

		// Older HTTP
		// keep-alive header indicates persistant connection 
		if (getheader("keep-alive"))
			return false;

		// TODO: some special case handling for Akamai and netscape maybe?
		// (see _check_close() in python httplib.py for details)

		return true;
	}

	void Finish()
	{
		m_State = COMPLETE;

		// invoke the callback
		if (m_Connection.m_ResponseCompleteCB)
			(m_Connection.m_ResponseCompleteCB)(this, m_Connection.m_UserData);
	}
};



}	// end namespace happyhttp


#endif // HAPPYHTTP_H


