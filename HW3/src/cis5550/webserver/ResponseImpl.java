package cis5550.webserver;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import cis5550.tools.Logger;

public class ResponseImpl implements Response {
	private int statusCode;
    private String reasonPhrase;
    private byte[] body;
    private Map<String, List<String>> headers = new HashMap<>();
    
    private Route route;
    private RequestImpl request;
    private Object handlerResult;
    private boolean committed = false;
    private OutputStream outputStream;
    private SessionImpl session;
    
    private boolean bodySet = false;
    
    private static final Logger LOGGER = Logger.getLogger(Server.class);
    
    ResponseImpl(Route routeArg, RequestImpl requestArg, OutputStream outputStreamArg) {
    	route = routeArg;
    	request = requestArg;
    	outputStream = outputStreamArg;
    	try {
    		LOGGER.info("calling handle()");
			handlerResult = routeArg.handle(requestArg, this);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	if (requestArg.headers.containsKey("Set-Cookie")) {
    		LOGGER.info("UPDATING SESSION RESPONSE");
			session = requestArg.session();
			if (session.invalid == true) {
				session = null;
				LOGGER.info("INVALID SESSION");
			} else {
				header("Set-Cookie", "SessionID=" + session.id());
			}
			
    	}
    	
    	
    }
    
    public byte[] getBodyAsBytes() {
    	return body;
    }
    
    public Map<String, List<String>> getHeaders() {
    	return headers;
    }
    
    
    // The methods below are used to set the body, either as a string or as an array of bytes 
    // (if the application wants to return something binary - say, an image file). Your server
    // should send back the following in the body of the response:
    //   DONE * If write() has been called, ignore both the return value of Route.handle() and 
    //     any calls to body() and bodyAsBytes().
    //   DONE: * If write() has not been called and Route.handle() returns something other than null, 
    //     call the toString() method on that object and send the result.
    //   DONE: * If write() has not been called and Route.handle returns null(), use the value from
    //     the most recent body() or bodyAsBytes() call.
    //   IMPLEMENT: * If none of write(), body(), and bodyAsBytes() have been called and Route.handle returns null,
    //     do not send a body in the response.
	@Override
	public void body(String body) {
		if (!committed) {			
			if (handlerResult != null) {
				this.body = handlerResult.toString().getBytes();
			} else {
				if (body == null) {
					LOGGER.info("body null");
				}
                this.body = body.getBytes();
            }
			bodySet = true;			
		}
	
		
	}

	@Override
	public void bodyAsBytes(byte[] bodyArg) {
		if (!committed) {			
			if (handlerResult != null) {
				this.body = handlerResult.toString().getBytes();
			} else {
                this.body = bodyArg;
            }
			bodySet = true;			
		}
	}

	// This method adds a header. For instance, header("Cookie", "abc=def") should cause your
	// server to eventually send a header line "Cookie: abc=def". This method can be called 
	// multiple times with the same header name; the result should be multiple header lines. 
	// type(X) should be the same as header("Content-Type", X). If write() has been called, 
	// these methods should have no effect.
	@Override
	public void header(String name, String value) {
		if (!committed) {
            headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
		}
	}

	@Override
	public void type(String contentType) {
		if (!committed) {
            header("Content-Type", contentType);
        }
	}

	// This method sets the status code and the reason phrase. If it is called more than once,
	// use the latest values. If it is never called, use 200 and "OK". If write() has been
	// called, status() should have no effect.
	@Override
	public void status(int statusCode, String reasonPhrase) {
		this.statusCode = statusCode;
        this.reasonPhrase = reasonPhrase;
	}

	// This method can be used to send data directly to the connection, without buffering it
	// in an object in memory. The first time write() is called, it should 'commit' the 
	// response by sending out the status code/reason phrase and any headers that have been
	// set so far. Your server should 1) add a 'Connection: close' header, and it should 
	// 2) NOT add a Content-Length header in this case. Then, and in any subsequent calls, 
	// it should simply write the provided bytes directly to the connection.
	@Override
	public void write(byte[] b) throws Exception {
		LOGGER.info("calling write");
		if (!committed) {
	        commitResponse();
	    }
		LOGGER.info("writing: " + new String(b, StandardCharsets.UTF_8));
	    outputStream.write(b);
	    outputStream.flush();
	}
	
	private void commitResponse() throws IOException {
	    // Add the 'Connection: close' header
		header("Connection", "close");
	    
	    // Start with the status line
	    String statusLine = "HTTP/1.1 200 OK\r\n";
	    outputStream.write(statusLine.getBytes(StandardCharsets.UTF_8));
	    
	    // Send the headers
	    LOGGER.info("HEADERS");
	    for (Entry<String, List<String>> header : headers.entrySet()) {
	    	for (String value : header.getValue()) {
	    		String headerLine = header.getKey() + ": " + value + "\r\n";
	    		LOGGER.info("headerline: " + headerLine);
		        outputStream.write(headerLine.getBytes(StandardCharsets.UTF_8));
	    	}
	    }
	    
	    // Header section ends with an empty line
	    outputStream.write("\r\n".getBytes(StandardCharsets.UTF_8));
	    outputStream.flush();	    
	    committed = true;
	}
	
	public boolean getCommitted() {
		return committed;
	}

	// EC
//	TODO: Implement below: If the application calls redirect(U,c), the server should redirect the client to URL U, using response code c (which can
//	be 301, 302, 303, 307, or 308).
	@Override
	public void redirect(String url, int responseCode) {
		if (!committed) {
			this.statusCode = responseCode;
			 switch (responseCode) {
	            case 301:
	                this.reasonPhrase = "Moved Permanently";
	                break;
	            case 302:
	                this.reasonPhrase = "Found";
	                break;
	            case 303:
	                this.reasonPhrase = "See Other";
	                break;
	            case 307:
	                this.reasonPhrase = "Temporary Redirect";
	                break;
	            case 308:
	                this.reasonPhrase = "Permanent Redirect";
	                break;
	            default:
	                LOGGER.error("Unsupported redirect status code: " + responseCode);
	                return;
	        }
			 
	        header("Location", url);
	        try {
	        	commitResponse();
	        } catch (IOException e) {
				LOGGER.error("error comitting redirect response");
			}
		} else {
	        LOGGER.warn("Response already committed. Cannot perform redirect.");
		}
        
	}

	// EC
	@Override
	public void halt(int statusCode, String reasonPhrase) {
		this.statusCode = statusCode;
        this.reasonPhrase = reasonPhrase;

	}

}
