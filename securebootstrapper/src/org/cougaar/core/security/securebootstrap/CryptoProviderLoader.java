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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;


/**
 * @author srosset
 *
 */
public class CryptoProviderLoader {
  private static Logger _logger = Logger.getInstance();
  private static CryptoProviderLoader singleton;
  
  private CryptoProviderLoader() {
  }
  
  public synchronized static CryptoProviderLoader getInstance() {
    if (singleton == null) {
      singleton = new CryptoProviderLoader();
    }
    return singleton;
  }
  
  public void loadCryptoProviders(ClassLoader cl)
  {
    if (_logger.isDebugEnabled()) {
      _logger.debug("Loading cryptographic providers");
    }
    String config_path = System.getProperty("org.cougaar.config.path");
    /*
     FileFinder fileFinder = FileFinderImpl.getInstance(config_path);
     File file = fileFinder.locateFile("cryptoprovider.conf");
     */
    
    StringBuffer configfile=new StringBuffer();
    String configproviderpath=
      System.getProperty("org.cougaar.core.security.crypto.cryptoProvidersFile");
    String sep = File.separator;
    if((configproviderpath==null)||(configproviderpath=="")) {
      configproviderpath=System.getProperty("org.cougaar.install.path");    
      if((configproviderpath!=null)||(configproviderpath!="")) {
        configfile.append(configproviderpath);
        configfile.append(sep+"configs"+sep+"security"+sep+"cryptoprovider.conf");
      }
      else {
        System.err.println("Error loading cryptographic providers: org.cougaar.install.path not set");
        return;
      }
    }
    else {
      configfile.append(configproviderpath);
    }
    File file=new File(configfile.toString());
    
    if(file == null || !file.exists()) {
      _logger.warn("Cannot find Cryptographic Provider Configuration file");
      return;
    }
    try {
      FileReader filereader=new FileReader(file);
      BufferedReader buffreader=new BufferedReader(filereader);
      String linedata=new String();
      int index=0;
      String providerclassname="";
      while((linedata=buffreader.readLine())!=null) {
        linedata.trim();
        if(linedata.startsWith("#")) {
          continue;
        }
        if(linedata.startsWith("security.provider")) {
          index=linedata.indexOf('=');
          if(index!=-1) {
            providerclassname=linedata.substring(index+1);
            if (_logger.isDebugEnabled()) {
              _logger.debug("Loading provider " + providerclassname);
            }
            try {
              if (_logger.isDebugEnabled()) {
                _logger.debug("Loading " + providerclassname
                    + " with " + cl.toString());
              }
              Class c = Class.forName(providerclassname, true, cl);
              Object o = c.newInstance();
              if (o instanceof java.security.Provider) {
                Security.addProvider((java.security.Provider) o);
              }
            } 
            catch(Exception e) {
              _logger.warn("Error loading security provider (" + e + ")"); 
            }
          }
        }
      }
    }
    catch(FileNotFoundException fnotfoundexp) {
      _logger.warn("cryptographic provider configuration file not found");
    }
    catch(IOException ioexp) {
      _logger.warn("Cannot read cryptographic provider configuration file", ioexp);
    }
    if (_logger.isDebugEnabled()) {
      printProviderProperties();
    }
  }
  
  public void printProviderProperties() {
    Provider[] pv = Security.getProviders();
    for (int i = 0 ; i < pv.length ; i++) {
      _logger.debug("Provider[" + i + "]: "
          + pv[i].getName() + " - Version: " + pv[i].getVersion());
      _logger.debug(pv[i].getInfo());
      // List properties
      String[] properties = new String[1];
      properties = (String[]) pv[i].keySet().toArray(properties);
      Arrays.sort(properties);
      for (int j = 0 ; j < properties.length ; j++) {
        String key, value;
        key = (String) properties[j];
        value = pv[i].getProperty(key);
        _logger.debug("Key: " + key + " - Value: " + value);
      }
    }
  }
  

}
