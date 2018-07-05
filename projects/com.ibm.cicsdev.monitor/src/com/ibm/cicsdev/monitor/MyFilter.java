package com.ibm.cicsdev.monitor;

import java.io.IOException;
import java.text.SimpleDateFormat;

import com.ibm.websphere.security.WSSecurityException;
import com.ibm.websphere.security.WSSecurityHelper;
import com.ibm.websphere.security.auth.CredentialDestroyedException;
import com.ibm.websphere.security.auth.WSSubject;
import com.ibm.websphere.security.cred.WSCredential;
import javax.security.auth.Subject;
import javax.security.auth.login.CredentialExpiredException;

import java.util.Date;
import java.util.Iterator;
import java.util.Set;

import com.ibm.cics.server.InvalidRequestException;
import com.ibm.cics.server.Task;
import com.ibm.jzos.ZUtil;

import javax.servlet.*;

/*
 * Servlet filter for CICS Liberty, Logs request credentials and callers IP address
 */
public class MyFilter implements Filter {
	
	
	private static SimpleDateFormat dfTime = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	

	public void init(FilterConfig arg0) throws ServletException {
	}

	/*
	 * doFilter called for every servlet invocation 
	 */
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain filterchain) throws IOException, ServletException {

		printMsg("Starting sevlet filter processing for servlet: " + req.getServletContext().getServletContextName().toString());
		
		printMsg("Request received from IP address: "+ req.getRemoteAddr() );
			
		printMsg("Credentials for request:" + getCredentials());
		
		filterchain.doFilter(req, resp); 

	}

	/*
	 * Get the credentials under which this servlet is running
	 * 
	 * returns a String composed of Subject/Realm, CICS task userid, region ID
	 */
	public String getCredentials() {

		String creds = "Unknown";
		String publicUserid = "";
		String realm = "";
		String libertyUser = "";
		String cicsUser = "";
		String regionUser = "";

		// Check if security enabled in Liberty
		if (WSSecurityHelper.isServerSecurityEnabled()) {

			try {
				// Get the Java subject and extract userid and security realm
				Subject callerSubject;
				WSCredential wsCred;

				callerSubject = WSSubject.getCallerSubject();
				if (callerSubject != null) {
					Set<WSCredential> wsCredentials = callerSubject.getPublicCredentials(WSCredential.class);
					Iterator<WSCredential> wsCredentialsIterator = wsCredentials.iterator();
					if (wsCredentialsIterator.hasNext()) {
						wsCred = wsCredentialsIterator.next();
						publicUserid = wsCred.getSecurityName();
						realm = wsCred.getRealmName();
						libertyUser = publicUserid + "/" + realm;
					}
				}

				// Get CICS Task userid
				cicsUser = Task.getTask().getUSERID();

				// Get ID of current thread, to log the region userid 
				regionUser = ZUtil.getCurrentUser();

				creds = ("Java subject:" + libertyUser + " CICS userid:" + cicsUser + "region ID:" + regionUser);

			} catch (CredentialExpiredException | CredentialDestroyedException | WSSecurityException
					| InvalidRequestException e1) {
				e1.printStackTrace();
			}
		} else {
			creds = "Security disabled";
		}

		return creds;
	}

	/* 
	 * Log output messages with CICS task ID and time prefix
	 */
	public static void printMsg (String msg) {
		int taskInt = Task.getTask().getTaskNumber();
		System.out.println( dfTime.format(new Date()) + " Task("+taskInt+") "  + msg );
		System.out.flush();
	}
	
	public void destroy() {
	}
	
	
}
