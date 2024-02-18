package cis5550.webserver;

import java.util.concurrent.ConcurrentHashMap;

import cis5550.tools.Logger;

public class SessionImpl implements Session {
	String id;
	final long creationTime;
	long lastAccessedTime;
	int maxActiveInterval;
	ConcurrentHashMap<String, Object> attributes = new ConcurrentHashMap<>(); // Session attributes
	boolean invalid = false;
	private static final Logger LOGGER = Logger.getLogger(Server.class);

	
	public SessionImpl(String id) {
		this.id = id;
		this.creationTime = System.currentTimeMillis();
        this.lastAccessedTime = creationTime;
	}

	@Override
	public String id() {
		return id;
	}

	@Override
	public long creationTime() {
		return creationTime;
	}

	@Override
	public long lastAccessedTime() {
		return lastAccessedTime;
	}

	@Override
	public void maxActiveInterval(int seconds) {
		this.maxActiveInterval = seconds;
		
	}

	@Override
	public void invalidate() {
		invalid = true;
		attributes.clear();
	}

	@Override
	public Object attribute(String name) {
		
		return attributes.get(name);
	}

	@Override
	public void attribute(String name, Object value) {
		LOGGER.info("adding attirbute: " + name);
		attributes.put(name, value);
	}
	
	public void updateLastAccessedTime() {
		lastAccessedTime = System.currentTimeMillis();
	}

}
