package cis5550.webserver;

import static cis5550.webserver.Server.get;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingDeque;

import java.util.Date;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import javax.net.ssl.*;
import java.security.*;
import java.security.cert.CertificateException;
import javax.net.ServerSocketFactory;

import cis5550.tools.*;


public class Server {
	private static final Logger LOGGER = Logger.getLogger(Server.class);
	private static final int NUM_WORKERS = 100;
    private static final String CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-";
    private static final int EXPIRY_SECONDS = 5;
	
	private static Server instance = null;
	private static boolean isRunning = false;
	private static int port = 80;
	private static int securePort = -1;
	private static String location;
    private static final Map<String, Route> routingTable = new HashMap<>();
    private static Map<String, SessionImpl> sessionTable = new ConcurrentHashMap<>();
    private static SessionImpl session = null;
	
	public static void run(String route) throws IOException, InterruptedException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, KeyManagementException { 
//		if (location == null) {
//			return;
//		}
				
		ServerSocket serverSocket = new ServerSocket(port);
		LOGGER.info("Unsecure listening on port "  + port);
		
		String pwd = "secret";
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(new FileInputStream("keystore.jks"), pwd.toCharArray());
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
		keyManagerFactory.init(keyStore, pwd.toCharArray());
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
		ServerSocketFactory factory = sslContext.getServerSocketFactory();
		ServerSocket serverSocketTLS = factory.createServerSocket(securePort);
		LOGGER.info("Secure listening on port "  + securePort);
		
		BlockingQueue<Socket> queue = new LinkedBlockingDeque<>(); 
        ExecutorService executorService = Executors.newFixedThreadPool(NUM_WORKERS);
		
		// Initialize worker threads
        for (int i = 0; i < NUM_WORKERS; i++) {
            executorService.submit(() -> {
            	try {
                    while (true) {
                        Socket soc = queue.take(); // Take a socket from the queue
        				processRequest(soc, location);
        				soc.close();
                    }
                } catch (InterruptedException e) {
                    LOGGER.info("Worker thread interrupted");
                } catch (IOException e) {
                    LOGGER.warn("Error processing request: " + e.getMessage());
                }
            });
        }
        
        new Thread(() -> {
            try {
                serverLoop(serverSocket, queue);
            } catch (IOException e) {
                LOGGER.error("Error in HTTP server loop: " + e.getMessage());
            }
        }).start();

        new Thread(() -> {
            try {
                serverLoop(serverSocketTLS, queue);
            } catch (IOException e) {
                LOGGER.error("Error in HTTPS server loop: " + e.getMessage());
            }
        }).start();
        
	}
	
	private static void serverLoop(ServerSocket s, BlockingQueue<Socket> queue) throws IOException {
		// Server main loop for accepting connections
		while (true) { 
        	Socket soc = s.accept(); 
			LOGGER.info("Client connected to server");
			queue.add(soc);
			LOGGER.info("Adding socket to queue");
        }	
	}
	
	private static void expireOldSessions() {
		LOGGER.info("checking for expired sessions out");
		while (!Thread.currentThread().isInterrupted()) {
			LOGGER.info("checking for expired sessions in");
			long currentTimeMillis = System.currentTimeMillis();
			
			Iterator<Entry<String, SessionImpl>> iterator = sessionTable.entrySet().iterator();
			LOGGER.info("sessiontable size: " + sessionTable.size());
	        while (iterator.hasNext()) {
	            Entry<String, SessionImpl> entry = iterator.next();
	            Session session = entry.getValue();
	            LOGGER.info("checking if valid: " + session.id());
	            if (currentTimeMillis - session.lastAccessedTime() > EXPIRY_SECONDS * 1000) {
	            	LOGGER.info("Invalidating session: " + session.id());
	            	session.invalidate();
	            	session = null;
	                iterator.remove(); 
	            }
	        }
	        try {
                Thread.sleep(1000); // 1000 milliseconds = 1 second
            } catch (InterruptedException e) {
                LOGGER.info("Session expiry thread was interrupted.");
                Thread.currentThread().interrupt(); 
                break; 
            }
		}
	}
	
	
	
	private static void processRequest(Socket soc, String directory) throws IOException {
		while (true) {
			if (soc.isClosed()) return;
			byte[] buffer = new byte[4096];
			int bytesRead;
			StringBuilder requestBuilder = new StringBuilder();
			while ((bytesRead = soc.getInputStream().read(buffer)) != -1) {
	            requestBuilder.append(new String(buffer, 0, bytesRead));
	            if (requestBuilder.toString().contains("\r\n\r\n")) {
	                break;
	            }
			}
			if (bytesRead == -1) {
				soc.close();
				return;
			}
			
			String request = requestBuilder.toString();
			LOGGER.info("request above: " + request);
	
			// Convert the received bytes to strings
	        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(request.getBytes());
	        InputStreamReader inputStreamReader = new InputStreamReader(byteArrayInputStream);
	        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
	        
	        // Parse request line
	        String requestLine = bufferedReader.readLine();
	        if (requestLine == null) {
	        	soc.close();
	        	return;
	        }
	        LOGGER.info("Request: " + requestLine);
	        	        
	        String[] splited = requestLine.split("\\s+");
	        
	        if (splited.length != 3) {
	        	sendResponse(soc, 400);
	        	return;
	        }
	        
	        if (splited[0].equals("GET") || splited[0].equals("HEAD") || splited[0].equals("POST") || splited[0].equals("PUT")) {
	        	boolean get = splited[0].equals("GET"); 
	        	String url = splited[1];
	        	String returnUrl = directory + url;
	        	String protocol = splited[2];
	        	
	        	if (url.contains("..")) {
	        		sendResponse(soc, 403);
	        		return;
	        	}
	        	if (!protocol.equals("HTTP/1.1")) {
	        		sendResponse(soc, 505);
	        		return;
	        	}
	        	
	        	// Get extension
	        	String extension = "application/octet-stream";
	        	String[] urlSplit = url.split("\\.");
	        	System.out.println(urlSplit.length);
	        	if (urlSplit[urlSplit.length-1].equals("txt")) {
	        		extension = "text/plain";
	        	} else if (urlSplit[urlSplit.length-1].equals("jpg") ||
	        			urlSplit[urlSplit.length-1].equals("jpeg")) {
	        		extension = "image/jpeg";
	        	} else if (urlSplit[urlSplit.length-1].equals("html")) {
	        		extension = "text/html";
	        	}
	        	
	        	// Parse headers
	        	Map<String, String> headers = new HashMap<>();
	        	
	        	String headerLine;
	        	while ((headerLine = bufferedReader.readLine()) != null && !headerLine.isEmpty()) {
	        	    LOGGER.info("Header: " + headerLine);
	        	    int separatorIndex = headerLine.indexOf(":");
	        	    if (separatorIndex != -1) {
	        	        String key = headerLine.substring(0, separatorIndex).trim().toLowerCase();
	        	        String value = headerLine.substring(separatorIndex + 1).trim();
	        	        headers.put(key, value);
	        	    }
	        	}

	        	int headersAndSeparatorLength = request.indexOf("\r\n\r\n") + 4; // 4 characters for "\r\n\r\n"
	        	String body = "";
	        	if (headers.containsKey("content-length")) {
	        	    int contentLength = Integer.parseInt(headers.get("content-length"));
	        	    int bodyStartIndex = headersAndSeparatorLength;
	        	    
	        	    if (request.length() >= bodyStartIndex + contentLength) {
	        	        body = request.substring(bodyStartIndex, bodyStartIndex + contentLength);
	        	    } 
	        	}
	        	Map<String, String> cookies = new HashMap<>();
	        	if(headers.containsKey("cookie")) {
	        		String cookiesStr = headers.get("cookie");
	                String[] cookiesArr = cookiesStr.split("; ");
	                for (String cookie : cookiesArr) {
	                    String[] cookieParts = cookie.split("=", 2);
	                    if (cookieParts.length == 2) {
	                        cookies.put(cookieParts[0], cookieParts[1]);
	                    }
	                }
	                
	                // extract the cookie with the name SessionID, if it exists; if it does, and your Map contains a
	                // session for that ID, update that session’s last-accessed time and make sure that the session() method
	                // will return it when called. 
	                LOGGER.info("containskey: " + cookies.containsKey("SessionID"));
	                if (cookies.containsKey("SessionID") && sessionTable.containsKey(cookies.get("SessionID"))) {
	                	SessionImpl currSession = sessionTable.get(cookies.get("SessionID"));
	                	currSession.updateLastAccessedTime(); 
	                	session = currSession;
	                }
	               
	        	}
	        	for (String cookieKey : cookies.keySet()) {
	        		LOGGER.info(cookieKey + ": " + cookies.get(cookieKey));
	        	}
	        	
	        	byte bodyBytes[] = body.getBytes();
	        	LOGGER.info("Body from parse: " + body);
	            LOGGER.info("return url: " + returnUrl);
	            	            
	            // Close stream
	            bufferedReader.close();
	            inputStreamReader.close();
	            byteArrayInputStream.close();
	            
                PrintStream output = new PrintStream(soc.getOutputStream(), true);
	            
	        	// Iterate over the routes
	        	for (String key : routingTable.keySet()) {
	        		String[] keyParts = key.split(":", 2);
	        		String method = keyParts[0];
	        		String route = keyParts[1];
	        		
	        		Map<String, String> pathParams = new HashMap<>();
        	        String[] urlParts = url.split("\\?");
	        		String urlNoParams = urlParts[0];
	        		if (matchPattern(splited[0], urlNoParams, method, route, pathParams)) {
	        			Map<String, String> queryParams = new HashMap<>();
	        			
	    	            if (headers.containsKey("content-type") && headers.get("content-type").equals("application/x-www-form-urlencoded")) {
	    	            	queryParams.putAll(parseQueryParams(body));
	    	            }
	        			
	        			if (urlParts.length > 1) {
	        				queryParams.putAll(parseQueryParams(urlParts[1]));
	        			}
	        			Route currRoute = routingTable.get(key);
	        			// instantiate Request and Response objects
	        			LOGGER.info("setting request and reponse at route " + key);
	        			LOGGER.info("url " + url);
	        			RequestImpl requestInst = new RequestImpl(method, url, protocol, headers, queryParams, pathParams, null, bodyBytes, getInstance());
	        			//RequestImpl(String methodArg, String urlArg, String protocolArg, Map<String,String> headersArg, Map<String,String> queryParamsArg, Map<String,String> paramsArg, InetSocketAddress remoteAddrArg, byte bodyRawArg[], Server serverArg) {
	        			ResponseImpl responseInst = new ResponseImpl(currRoute, requestInst, output);
	        			try {
	        				if (responseInst.getCommitted()) {
	        					soc.close();
	        				}
	        				Object handlerResult = currRoute.handle(requestInst, responseInst);
							sendDynamicContent(soc, requestInst, responseInst, handlerResult);
							return;
						} catch (Exception e) {
							if (!responseInst.getCommitted()) {
								sendResponse(soc, 500);
							} else {
								soc.close();
							}
							LOGGER.info(e.getMessage());
			        		return;
						}
	        		}
	        	}
	        	
	        	if(splited[0].equals("POST") || splited[0].equals("PUT")) {
		        	sendResponse(soc, 405);
		        	return;
	        	}
	        	sendStaticFile(returnUrl, soc, headers, output, extension, protocol, get);
	        } else {
	        	sendResponse(soc, 501);
	        }
		}
	}
	
	private static boolean matchPattern(String urlMethod, String url, String routeMethod, String pathPattern, Map<String, String> pathParams) {
		if (routeMethod.equals(urlMethod) && pathPattern.equals(url)) return true;
		String[] urlParts = url.split("/");
		String[] patternParts = pathPattern.split("/");
		if (urlParts.length != patternParts.length) {
            return false;
        }
		for (int i = 0; i < urlParts.length; i++) {
            if (!patternParts[i].startsWith(":")) {
                // Key
                if (!urlParts[i].equals(patternParts[i])) {
                    return false;
                }
            } else {
                // Named parameter
                String paramName = patternParts[i].substring(1); // Remove ":"
                LOGGER.info("adding- " + paramName + ": " + urlParts[i]);
                pathParams.put(paramName, urlParts[i]);
            }
        }
		
		return true;
	}
	
	private static Map<String, String> parseQueryParams(String queryString) {
		Map<String, String> queryParams = new HashMap<>();
		
		String[] pairs = queryString.split("&");
        for (String pair : pairs) {
            // Split each pair into name and value by "="
            int idx = pair.indexOf("=");
            try {
                String key = URLDecoder.decode(pair.substring(0, idx), "UTF-8");
                String value = URLDecoder.decode(pair.substring(idx + 1), "UTF-8");
                queryParams.put(key, value);
            } catch (UnsupportedEncodingException e) {
                LOGGER.error("error decoding query parameter: " + e.getMessage());
            } catch (StringIndexOutOfBoundsException e) {
                // "=" missing 
            	LOGGER.error("equals sign missing in query parameter: " + pair);
            }
        }
		
		
		return queryParams;
	}
	
	private static void sendDynamicContent(Socket soc, RequestImpl request, ResponseImpl response, Object handlerResult) {
		LOGGER.info("sending dynamic content");
		String responseBody = null;
		int len = 0;
		
		if (handlerResult != null) {
			responseBody = handlerResult.toString();
			len = responseBody.length(); 
			LOGGER.info("body: " + responseBody);
		}
		
		
		
		// 1 set the Content-Length header
		response.header("Content-Length", String.valueOf(len));
		
		// 2 write out the headers
		PrintWriter output;
		try {
			if (!response.getCommitted()) {
				output = new PrintWriter(soc.getOutputStream(), true);
				String extension = request.contentType();
				output.print(request.protocol() + " 200 OK\r\n");
		        output.print("Content-Type: " + extension + "\r\n");
		        output.print("Server: MyServer\r\n");
		        output.print("Content-Length: " + len);
		        for (String header : request.headers()) {
		        	LOGGER.info(header);
		        }
		        Map<String, List<String>> resHeaders = response.getHeaders();
		        if (resHeaders.size() > 0) {
		        	if (resHeaders.containsKey("Set-Cookie") && session != null) {
		        		// resHeaders.remove("Set-Cookie");
		        	}
	            	for (String key : resHeaders.keySet()) {
	            		List<String> values = resHeaders.get(key);
	            		for (String value : values) {
	            			String extraHeader = key + ": " + value;
	            			if ((key.equals("Set-Cookie") && request.headers().contains("Set-Cookie"))) {
	            				LOGGER.info("wanting to set extra header");
	            			} 
	            			LOGGER.info("Adding extraHeader- " + extraHeader); 
	            			output.print("\r\n" + extraHeader);
	            			
	            		}
	            	}
	            }
		        output.print("\r\n\r\n");
		        // 3 write out the body
		        if (len > 0) output.print(responseBody);
		        output.flush();
			} else {
				soc.close();
			}
			
		} catch (IOException e) {
			LOGGER.info("error processing header");
			e.printStackTrace();
		} 
	}
	
	private static void sendStaticFile(String returnUrl, Socket soc, Map<String, String> headers, PrintStream output, String extension, String protocol, Boolean get) throws IOException {
		// Read the file
        File file = new File(returnUrl);
        
        if (!file.exists()) {
        	sendResponse(soc, 404);
        	return;
        } else {
        	// Check for If-Modified Since
        	String ifMod = "if-modified-since";
            
        	if (headers.containsKey(ifMod)) {
				try {
					String ifModSince = headers.get(ifMod);
            	    SimpleDateFormat dateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
            	    
            	    Date ifModSinceDate = dateFormat.parse(ifModSince);
	            	Date currentDate = new Date(); 
	            	LOGGER.info("Current Date: " + dateFormat.format(currentDate));
			        LOGGER.info("If Mod Since Date: " + dateFormat.format(ifModSinceDate));
	                if (ifModSinceDate.after(currentDate)) {
	                    // The If-Modified-Since date is in the future, which is invalid. Do nothing
	                    LOGGER.info("If-Modified-Since date is in the future and is invalid.");
	                } else {
	                	long fileLastModified = file.lastModified();
						
						Date lastModifiedDate = new Date(fileLastModified);	     
	            	    dateFormat.setTimeZone(TimeZone.getTimeZone("EST"));
				        String lastModifiedDateStr = dateFormat.format(lastModifiedDate);
				        LOGGER.info("Last Modified Date: " + lastModifiedDateStr);
				        
            	        if (ifModSinceDate != null && fileLastModified <= ifModSinceDate.getTime()) {
            	            sendResponse(soc, 304); 
            	            return;
            	        }
	                }
				} catch (ParseException e) {
            	    // The passed If-Modified-Since date is invalid break from if condition
					System.out.println("ERROR: "+ e.getMessage());
                    LOGGER.info("Error parsing date: " + e.getMessage());
				}
        	}
        	
        	
            FileInputStream fileInputStream = new FileInputStream(file);
            int len =  (int) file.length();
            
            output.print(protocol + " 200 OK\r\n");
            output.print("Content-Type: " + extension + "\r\n");
            output.print("Server: MyServer\r\n");
            output.print("Content-Length: " + len);
            output.print("\r\n\r\n");

            if (extension.equals("text/plain")) {
            	byte[] fileContentBytes = new byte[(int) file.length()];
                fileInputStream.read(fileContentBytes);
                
                // Convert file content to String
                String fileContent = new String(fileContentBytes);
                fileInputStream.close();
                
                if (get) output.print(fileContent);
                output.flush();  
            } else if (extension.equals("application/octet-stream")) {
            	byte[] buffer2 = new byte[4096];
            	int bytesRead2;
            	if (get) {
            		while ((bytesRead2 = fileInputStream.read(buffer2)) != -1) {
                        output.write(buffer2, 0, bytesRead2);
                    }
            	}
            	fileInputStream.close();
            	output.flush();
            }   
            
        }
	}
	
	private static void sendResponse(Socket soc, int errCode) throws IOException {
		PrintWriter output = new PrintWriter(soc.getOutputStream(), true);
    	String errMsg = "";
    	
    	if (errCode == 304) {
    		errMsg = "304 Not Modified";
    	} else if (errCode == 400) {
			errMsg = "400 Bad Request";
		} else if (errCode == 403) {
			errMsg = "403 Forbidden";
		} else if (errCode == 404) {
			errMsg = "404 Not Found";
		} else if (errCode == 405) {
			errMsg = "405 Not Allowed";
		} else if (errCode == 500) {
			errMsg = "500 Internal Server Error";
		} else if (errCode == 501) {
			errMsg = "501 Not Implemented";
		} else if (errCode == 505) {
			errMsg = "505 HTTP Version Not Supported";
		} 
		
    	output.write("HTTP/1.1 " + errMsg + "\r\n");
        output.write("Content-Type: text/plain\r\n");
        output.write("Server: MyServer\r\n");
        output.write("Content-Length: " + errMsg.length());
        output.write("\r\n\r\n");
        output.write(errMsg);
        output.flush();
	}
	
	public static void get(String p, Route L) {
		getInstance();
		if (!isRunning) {
			isRunning = true;
			new Thread(() -> {
				try {					
					instance.run(p);
				} catch (IOException e) {
					e.printStackTrace();
				} catch (InterruptedException e) {
					e.printStackTrace();
				} catch (UnrecoverableKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (KeyManagementException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (CertificateException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}).start();
		}
		addRoute("GET", p, L);
	}
	
	public static void post(String p, Route L) {
		getInstance();
		if (!isRunning) isRunning = true;
		addRoute("POST", p, L);
	}
	
	public static void put(String p, Route L) {
		getInstance();
		if (!isRunning) isRunning = true;
		addRoute("PUT", p, L);
	}
	
	public static void port(int p) {
		getInstance();
		port = p;
	}
	
	public static void securePort(int p) {
		getInstance();
		securePort = p;
	}
	
	public static void addRoute(String method, String path, Route route) {
    	String k = method + ":" + path;
		routingTable.put(k, route);
		LOGGER.info("Added route: " + k);
    }
	
    public static Server getInstance() {
        if (instance == null) {
            instance = new Server();
        }
        return instance;
    }
    
    public static SessionImpl session() {
    	if (session == null) {
    		String id = getRandomId(20);
    		LOGGER.info("UPDATING SESSION SEVER SESSION");
    		session = new SessionImpl(id);
    		sessionTable.put(id, session);
    	}
    	return session;
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
    
    
	public static class staticFiles {
		
		public static void location(String s) {
			location = s;
            LOGGER.info("Serving static files from " + location);
            getInstance();
    		if (!isRunning) isRunning = true;
		}
		
	}

}



