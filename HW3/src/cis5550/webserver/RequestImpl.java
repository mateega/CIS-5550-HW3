package cis5550.webserver;

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

import cis5550.tools.Logger;

import java.net.*;
import java.nio.charset.*;
import java.security.SecureRandom;


class RequestImpl implements Request {
  String method;
  String url;
  String protocol;
  InetSocketAddress remoteAddr;
  Map<String,String> headers;
  Map<String,String> queryParams;
  Map<String,String> params;
  byte bodyRaw[];
  Server server;
  SessionImpl session;
  private static final String CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-";
  private static final int EXPIRY_MILLISECONDS = 1000;
  private static final Logger LOGGER = Logger.getLogger(Server.class);
  
  Map<String, String> cookies = new HashMap<>();
  private static Map<String, SessionImpl> sessionTable = new ConcurrentHashMap<>();
  
  
  RequestImpl(String methodArg, String urlArg, String protocolArg, Map<String,String> headersArg, Map<String,String> queryParamsArg, Map<String,String> paramsArg, InetSocketAddress remoteAddrArg, byte bodyRawArg[], Server serverArg) {
    method = methodArg;
    url = urlArg;
    remoteAddr = remoteAddrArg;
    protocol = protocolArg;
    headers = headersArg;
    queryParams = queryParamsArg;
    params = paramsArg;
    bodyRaw = bodyRawArg;
    server = serverArg;
    
    new Thread(() -> {
    	try {
			Thread.sleep(0); // 1000
			expireOldSessions();
		} catch (InterruptedException e) {
			LOGGER.error("Error with expiring old sessions: " + e.getMessage());
		} 
    }).start();
  }

  public String requestMethod() {
  	return method;
  }
  public void setParams(Map<String,String> paramsArg) {
    params = paramsArg;
  }
  public int port() {
  	return remoteAddr.getPort();
  }
  public String url() {
  	return url;
  }
  public String protocol() {
  	return protocol;
  }
  public String contentType() {
  	return headers.get("content-type");
  }
  public String ip() {
  	return remoteAddr.getAddress().getHostAddress();
  }
  public String body() {
    return new String(bodyRaw, StandardCharsets.UTF_8);
  }
  public byte[] bodyAsBytes() {
  	return bodyRaw;
  }
  public int contentLength() {
  	return bodyRaw.length;
  }
  public String headers(String name) {
  	return headers.get(name.toLowerCase());
  }
  public Set<String> headers() {
  	return headers.keySet();
  }
  public String queryParams(String param) {
  	return queryParams.get(param);
  }
  public Set<String> queryParams() {
  	return queryParams.keySet();
  }
  public String params(String param) {
    return params.get(param);
  }
  public Map<String,String> params() {
    return params;
  }

	//This method is used to either look up the current session, if any, or to create a new session.
	// If this is method is called multiple times while handling the same request, it should always 
	// return the same Session object; it should never return null. If the method is never called,
	// no Session object should be created.
	@Override
	public SessionImpl session() {
		LOGGER.info("session is null: " + (session==null));
		
		if (session != null) return session;
		
		if (headers.keySet().contains("cookie")) {
			parseCookies();
		} 
		
		// Extract the SessionID cookie, if it exists
        String sessionId = cookies.get("SessionID");
        
        if (sessionId != null && sessionTable.containsKey(sessionId)) {
            session = sessionTable.get(sessionId);
            session.updateLastAccessedTime();
        } else {
            sessionId = getRandomId(20); 
            session = new SessionImpl(sessionId); 
            sessionTable.put(sessionId, session);
            
            headers.put("Set-Cookie", session.id());
			LOGGER.info("adding set-cookie header");
        }
 
        
        return session;
	}
	
	private void parseCookies() {
		String cookiesStr = headers.get("cookie");
        String[] cookiesArr = cookiesStr.split("; ");
        for (String cookie : cookiesArr) {
            String[] cookieParts = cookie.split("=", 2);
            if (cookieParts.length == 2) {
                cookies.put(cookieParts[0], cookieParts[1]);
            }
        } 
	}
	
	public boolean hasSession() {
		return session != null;
	}
	
	public void clearSession() {
		session = null;
	}
	
	private static String getRandomId(int id_length) {
    	SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(id_length);
        for (int i = 0; i < id_length; i++) {
            int index = random.nextInt(CHARACTERS.length());
            sb.append(CHARACTERS.charAt(index));
        }
        return sb.toString();
    }
	
	private static void expireOldSessions() {
		while (!Thread.currentThread().isInterrupted()) {
			long currentTimeMillis = System.currentTimeMillis();
			
			Iterator<Entry<String, SessionImpl>> iterator = sessionTable.entrySet().iterator();
			// LOGGER.info("sessiontable size: " + sessionTable.size());
	        while (iterator.hasNext()) {
	            Entry<String, SessionImpl> entry = iterator.next();
	            Session session = entry.getValue();
	            // LOGGER.info("checking if valid: " + session.id());
	            if (currentTimeMillis - session.lastAccessedTime() > EXPIRY_MILLISECONDS) {
	            	LOGGER.info("Invalidating session: " + session.id());
	            	session.invalidate();
	            	session = null;
	                iterator.remove(); 
	            }
	        }
	        try {
                Thread.sleep(100); // 1000 milliseconds = 1 second
            } catch (InterruptedException e) {
                LOGGER.info("Session expiry thread interrupted");
                Thread.currentThread().interrupt(); 
                break; 
            }
		}
	}

}
