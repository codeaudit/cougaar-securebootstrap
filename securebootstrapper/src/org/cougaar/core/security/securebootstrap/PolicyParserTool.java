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

import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import sun.security.provider.PolicyParser;

/**
 * @author srosset
 *
 * This class is used to build the Java policy used in the Cougaar system.
 * As of December 6th 2004, keys used to sign JAR files have been updated.
 * This is because old keys expire in July 2005.
 * We want to support both old keys and new keys during a transition period.
 * This means the secure class loader and the Java security manager should
 * accept JAR files signed either by the old key or the new key.
 * There is a small issue related to the Java policy. The default Java policy
 * provider does not allow to specify "grant" entries with signer A OR signer B.
 * The policy supports conjunction but not disjunction:
 * grant SignedBy "A,B" codebase "foo.jar" means foo.jar must be signed by A AND B.
 * There is no way to state "foo.jar must be signed by A OR B.
 * This tool reads the Cougaar policy and generates entries to support both
 * the "old" signers and the "new" signers.  
 */
public class PolicyParserTool {

  public void processJavaPolicy(String oldPolicyFile, String newPolicyFile) {
    PolicyParser policyparser = new PolicyParser(false);
    try {
      // Read policy file.
      policyparser.read(new FileReader(oldPolicyFile));
      System.out.println(policyparser.toString());
      Enumeration en = policyparser.grantElements();
      List newGrantEntries = new ArrayList();
      while (en.hasMoreElements()) {
        PolicyParser.GrantEntry ge = (PolicyParser.GrantEntry)en.nextElement();
        System.out.println(ge.codeBase + ":" + ge.signedBy);
        if (ge.signedBy != null) {
          // Clone grant entry and change signer from <alias> to <alias-old>
          PolicyParser.GrantEntry clone = (PolicyParser.GrantEntry)ge.clone();
          // Accept old keys.
          clone.signedBy = ge.signedBy + "-old";
          newGrantEntries.add(clone);
        }
      }
      Iterator it = newGrantEntries.iterator();
      while (it.hasNext()) {
        PolicyParser.GrantEntry ge = (PolicyParser.GrantEntry)it.next();
        policyparser.add(ge);
      }
      FileWriter filewriter = new FileWriter(newPolicyFile);
      policyparser.write(filewriter);
      filewriter.close();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
  
  public static void main(String args[]) {
    if (args.length != 2) {
      System.out.println("Usage: PolicyParserTool oldPolicyFile newPolicyFile");
      System.exit(-1);
    }
    new PolicyParserTool().processJavaPolicy(args[0], args[1]);
  }
}
