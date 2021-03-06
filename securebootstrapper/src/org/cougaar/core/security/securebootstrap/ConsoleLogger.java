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

public class ConsoleLogger
  extends Logger
{
  public void debug(String s) {
    System.out.println("DEBUG:" + s);
  }
  public void debug(String s, Exception e) {
    System.out.println("DEBUG:" + s);
    e.printStackTrace();
  }

  public void info(String s) {
    System.out.println("INFO:" + s);
  }
  public void info(String s, Exception e) {
    System.out.println("INFO:" + s);
    e.printStackTrace();
  }

  public void warn(String s) {
    System.out.println("WARN:" + s);
  }
  public void warn(String s, Exception e) {
    System.out.println("WARN:" + s);
    e.printStackTrace();
  }

  public void error(String s) {
    System.out.println("ERROR:" + s);
  }
  public void error(String s, Exception e) {
    System.out.println("ERROR:" + s);
    e.printStackTrace();
  }

  public boolean isDebugEnabled() {
    return true;
  }
  public boolean isInfoEnabled() {
    return true;
  }
  public boolean isWarnEnabled() {
    return true;
  }
  public boolean isErrorEnabled() {
    return true;
  }
}
