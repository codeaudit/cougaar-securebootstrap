/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.securebootstrap;

import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.cougaar.bootstrap.Bootstrapper;

public class BaseBootstrapper
extends Bootstrapper
{
  private String nodeName;
  private static Logger _logger = Logger.getInstance();
  
  protected String getNodeName() {
    return nodeName;
  }
  
  protected ClassLoader prepareVM(String classname, String[] args) {
    expandProperties();
    nodeName = parseNodename(args);
    ClassLoader cl = null;
    /*
     Setting up  policy & security manager
     if there is a policy and security manager then override the set 
     setPolicy & setSecurityManager methods. 
     */
    try {
      /* Set the Java policy for use by the security manager */
      _logger.debug("Setting policy");
      setPolicy();
      
      /* Set the Java security manager */
      if (_logger.isDebugEnabled()) {
        _logger.debug("Setting security manager");
      }
      setSecurityManager();
      
      /* Create a log file to report JAR file verification failures.
       This is only used when a secure class loader is set. */
      if (_logger.isDebugEnabled()) {
        _logger.debug("Creating Jar verification log");
      }
      createJarVerificationLog();
      
      /* Create the class loader. Load JAR files securely if
       * a secure class loader is used. */
      if (_logger.isDebugEnabled()) {
        _logger.debug("Creating class loader");
      }
      cl = super.prepareVM(classname, args);
      if (_logger.isDebugEnabled()) {
        _logger.debug("Class Loader:" + cl.getClass().getName());
      }
      
      /* Load cryptographic providers */
      CryptoProviderLoader.getInstance().loadCryptoProviders(cl);
    }
    catch (Exception e) {
      _logger.warn("Failed to launch "+classname, e);
    }
    
    return cl;
  }
  
  protected void launchMain(ClassLoader cl, String classname, String[] args) {
    if (_logger.isDebugEnabled()) {
      _logger.debug("Starting " + classname + " in "
          + System.getProperty("user.dir"));
      String s = "Arguments: ";
      for (int i = 0 ; i < args.length ; i++) {
        s = s + args[i] + " ";
      }
      _logger.debug(s);
    }
    super.launchMain(cl, classname, args);
  }
  
  protected String parseNodename(String[] args) {
    if (args.length <= 1) { // assemble command line from java VM properties
      String nodeClassName = "org.cougaar.core.node.Node";
      
      if (args.length == 1)
        nodeClassName = args[0];
      
      args = new String[4];
      args[0] = nodeClassName;
      args[1] = "-n";
      args[2] = System.getProperty("org.cougaar.node.name", "unknown-node");
      args[3] = "-c";
    }
    
    int argc = args.length;
    String check = null;
    String next = null;
    boolean sawname = false;
    for( int x = 0; x < argc;){
      check = args[x++];
      if (! check.startsWith("-") && !sawname) {
        sawname = true;
        if ("admin".equals(check)) 
          nodeName = "Administrator";
        else
          nodeName = check;
      }
      else if (check.equals("-n")) {
        nodeName = args[x++];
        sawname = true;
      }
    }
    return nodeName;
  }
  
  protected void setPolicy() {
  }
  
  protected void setSecurityManager() {
  }
  
  protected void createJarVerificationLog() {
  }
  
  protected ClassLoader createClassLoader(List urlList) {
    if (_logger.isDebugEnabled()) {
      _logger.debug("BaseBootstrapper.createClassLoader");
    }
    removeBootClasses(urlList);
    
    URL urls[] = (URL[]) urlList.toArray(new URL[urlList.size()]);
    return new BaseClassLoader(urls);
  }
  
  /** Remove bootstrap jar files from the list of URLs.
   * The list of URLs constructed by looking in the $CIP/lib and $CIP/sys
   * directories may contain jar files which are already part of the boot class path.
   * These jar files should be loaded by the system class loader directly.
   * Here, we remove the boot jar files from the list.
   */
  protected void removeBootClasses(List urlList) {
    String bootclassPathProp = System.getProperty("sun.boot.class.path");
    if (_logger.isDebugEnabled()) {
      _logger.debug("Boot Class Path:" + bootclassPathProp);
    }
    StringTokenizer st = new StringTokenizer(bootclassPathProp, ":");
    ArrayList bootclassPath = new ArrayList();
    while(st.hasMoreElements()) {
      String s = st.nextToken();
      try {
        // Need to resolve symbolic names
        URL url = new URL("file", "", (new File(s)).getCanonicalPath());
        bootclassPath.add(url);
      }
      catch (Exception ex) {
        _logger.warn("Unable to parse " + s + " url.");
      }
    }
    
    // Now, go through the list of URLs and remove the URLs which were
    // already specified in the boot class path.
    Iterator it = urlList.iterator();
    while (it.hasNext()) {
      URL aUrl = (URL) it.next();
      Iterator listIt = bootclassPath.iterator();
      while (listIt.hasNext()) {
        URL bootUrlElement = (URL) listIt.next();
        if (bootUrlElement.equals(aUrl)) {
          // Don't add the bootclass URLs
          if (_logger.isDebugEnabled()) {
            _logger.debug("Removing " + aUrl.toString() + " from URL list");
          }
          it.remove();
          break;
        }
      }
    }
  }
  
  public static void expandProperties() {
    boolean expandProperties =
      Boolean.valueOf(System.getProperty("org.cougaar.properties.expand",
                                           "true")).booleanValue();
    
    if (expandProperties) {
      Properties props = System.getProperties();
      Pattern p = Pattern.compile("\\$\\{([^\\$\\{\\}]*)\\}");
      Enumeration en = props.propertyNames();
      while (en.hasMoreElements()) {
        String key = (String)en.nextElement();
        String value = props.getProperty(key);
        boolean done = false;
        while (!done) {
          Matcher m = p.matcher(value);
          StringBuffer sb = new StringBuffer();
          done = true;
          while (m.find()) {
            done = false;
            String pKey = m.group(1);
            String pVal = System.getProperty(pKey, "null");
            m.appendReplacement(sb, pVal);
          }
          m.appendTail(sb);
          value = sb.toString();
        }
        props.setProperty(key, value);
      }
    }
  }
}
