/*
 * $Header: /home/jerenkrantz/tmp/commons/commons-convert/cvs/home/cvs/jakarta-commons//validator/src/test/org/apache/commons/validator/EmailTest.java,v 1.23 2004/01/19 14:11:33 rleland Exp $
 * $Revision: 1.23 $
 * $Date: 2004/01/19 14:11:33 $
 *
 * ====================================================================
 *
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2001-2004 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution, if
 *    any, must include the following acknowledgement:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowlegement may appear in the software itself,
 *    if and wherever such third-party acknowlegements normally appear.
 *
 * 4. The names, "Apache", "The Jakarta Project", "Commons", and "Apache Software
 *    Foundation" must not be used to endorse or promote products derived
 *    from this software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.validator;

import java.io.IOException;

import junit.framework.Test;
import junit.framework.TestSuite;

import org.xml.sax.SAXException;

/**                                                       
 * Performs Validation Test for e-mail validations.
 */                                                       
public class EmailTest extends TestCommon {

    /**
     * The key used to retrieve the set of validation
     * rules from the xml file.
     */
    protected static String FORM_KEY = "emailForm";

   /**
    * The key used to retrieve the validator action.
    */
   protected static String ACTION = "email";


   public EmailTest(String name) {                  
       super(name);                                      
   }                                                     

   /**
    * Start the tests.
    *
    * @param theArgs the arguments. Not used
    */
   public static void main(String[] theArgs) {
       junit.awtui.TestRunner.main(new String[] {EmailTest.class.getName()});
   }

   /**
    * @return a test suite (<code>TestSuite</code>) that includes all methods
    *         starting with "test"
    */
   public static Test suite() {
       // All methods starting with "test" will be executed in the test suite.
       return new TestSuite(EmailTest.class);
   }

   /**
    * Load <code>ValidatorResources</code> from 
    * validator-regexp.xml.
    */
   protected void setUp() throws IOException, SAXException {
      loadResources("validator-regexp.xml");
   }

   protected void tearDown() {
   }

   /**
    * Tests the e-mail validation.
    */
   public void testEmail() throws ValidatorException {
      // Create bean to run test on.
      ValueBean info = new ValueBean();

      info.setValue("jsmith@apache.org");
      valueTest(info, true);
   }

    /**
     * Tests the e-mail validation.
     */
    public void testEmailExtension() throws ValidatorException {
        // Create bean to run test on.
        ValueBean info = new ValueBean();

        info.setValue("jsmith@apache.org");
        valueTest(info, true);

        info.setValue("jsmith@apache.com");
        valueTest(info, true);

        info.setValue("jsmith@apache.net");
        valueTest(info, true);

        info.setValue("jsmith@apache.info");
        valueTest(info, true);

        info.setValue("jsmith@apache.infoo");
        valueTest(info, false);

        info.setValue("jsmith@apache.");
        valueTest(info, false);

        info.setValue("jsmith@apache.c");
        valueTest(info, false);
    }

   /**
    * <p>Tests the e-mail validation with a dash in 
    * the address.</p>
    */
   public void testEmailWithDash() throws ValidatorException {
      // Create bean to run test on.
      ValueBean info = new ValueBean();

      info.setValue("andy.noble@data-workshop.com");
      valueTest(info, true);

      info.setValue("andy-noble@data-workshop.-com");
       valueTest(info, true);
       info.setValue("andy-noble@data-workshop.c-om");
       valueTest(info,true);
       info.setValue("andy-noble@data-workshop.co-m");
       valueTest(info, true);


   }

   /**
    * <p>Tests the e-mail validation with a dot at the end of 
    * the address.</p>
    */
   public void testEmailWithDotEnd() throws ValidatorException {
      // Create bean to run test on.
      ValueBean info = new ValueBean();

      info.setValue("andy.noble@data-workshop.com.");
      valueTest(info, false);

   }

    /**
     * <p>Tests the e-mail validation with an RCS-noncompliant character in
     * the address.</p>
     */
    public void testEmailWithBogusCharacter() throws ValidatorException {
        // Create bean to run test on.
        ValueBean info = new ValueBean();

        info.setValue("andy.noble@\u008fdata-workshop.com");
        valueTest(info, false);
    
        // The ' character is valid in an email address.
        info.setValue("andy.o'reilly@data-workshop.com");
        valueTest(info, true);

        info.setValue("foo+bar@i.am.not.in.us.example.com");
        valueTest(info, true);
    }
   
   /**
    * Tests the email validation with commas.
    */
    public void testEmailWithCommas() throws ValidatorException {
        ValueBean info = new ValueBean();
        info.setValue("joeblow@apa,che.org");
        valueTest(info, false);
        info.setValue("joeblow@apache.o,rg");
        valueTest(info, false);
        info.setValue("joeblow@apache,org");
        valueTest(info, false);

    }

    /**
     * Write this test according to parts of RFC, as opposed to the type of character
     * that is being tested.
     * @throws ValidatorException
     */
    public void testEmailUserName() throws ValidatorException {
        ValueBean info = new ValueBean();
        info.setValue("joe1blow@apache.org");
        valueTest(info, true);
        info.setValue("joe$blow@apache.org");
        valueTest(info, true);
        info.setValue("joe-@apache.org");
        valueTest(info, true);
        info.setValue("joe_@apache.org");
        valueTest(info, true);

        //UnQuoted Special characters are invalid

        info.setValue("joe.@apache.org");
        valueTest(info, false);
        info.setValue("joe+@apache.org");
        valueTest(info, false);
        info.setValue("joe!@apache.org");
        valueTest(info, false);
        info.setValue("joe*@apache.org");
        valueTest(info, false);
        info.setValue("joe'@apache.org");
        valueTest(info, false);
        info.setValue("joe(@apache.org");
        valueTest(info, false);
        info.setValue("joe)@apache.org");
        valueTest(info, false);
        info.setValue("joe,@apache.org");
        valueTest(info, false);
        info.setValue("joe%45@apache.org");
        valueTest(info, false);
        info.setValue("joe;@apache.org");
        valueTest(info, false);
        info.setValue("joe?@apache.org");
        valueTest(info, false);
        info.setValue("joe&@apache.org");
        valueTest(info, false);
        info.setValue("joe=@apache.org");
        valueTest(info, false);

        //Quoted Special characters are valid
        info.setValue("\"joe.\"@apache.org");
        valueTest(info, true);
        info.setValue("\"joe+\"@apache.org");
        valueTest(info, true);
        info.setValue("\"joe!\"@apache.org");
        valueTest(info, true);
        info.setValue("\"joe*\"@apache.org");
        valueTest(info, true);
        info.setValue("\"joe'\"@apache.org");
        valueTest(info, true);
        info.setValue("\"joe(\"@apache.org");
        valueTest(info, true);
        info.setValue("\"joe)\"@apache.org");
        valueTest(info, true);
        info.setValue("\"joe,\"@apache.org");
        valueTest(info, true);
        info.setValue("\"joe%45\"@apache.org");
        valueTest(info, true);
        info.setValue("\"joe;\"@apache.org");
        valueTest(info, true);
        info.setValue("\"joe?\"@apache.org");
        valueTest(info, true);
        info.setValue("\"joe&\"@apache.org");
        valueTest(info, true);
        info.setValue("\"joe=\"@apache.org");
        valueTest(info, true);

    }

    /**
     * These test values derive directly from RFC 822 &
     * Mail::RFC822::Address & RFC::RFC822::Address perl test.pl
     * For traceability don't combine these test values with other tests.
     */
    TestPair[] testEmailFromPerl = {
        new TestPair("abigail@example.com", true),
        new TestPair("abigail@example.com ", true),
        new TestPair(" abigail@example.com", true),
        new TestPair("abigail @example.com ", true),
        new TestPair("*@example.net", true),
        new TestPair("\"\\\"\"@foo.bar", true),
        new TestPair("fred&barny@example.com", true),
        new TestPair("---@example.com", true),
        new TestPair("foo-bar@example.net", true),
        new TestPair("\"127.0.0.1\"@[127.0.0.1]", true),
        new TestPair("Abigail <abigail@example.com>", true),
        new TestPair("Abigail<abigail@example.com>", true),
        new TestPair("Abigail<@a,@b,@c:abigail@example.com>", true),
        new TestPair("\"This is a phrase\"<abigail@example.com>", true),
        new TestPair("\"Abigail \"<abigail@example.com>", true),
        new TestPair("\"Joe & J. Harvey\" <example @Org>", true),
        new TestPair("Abigail <abigail @ example.com>", true),
        new TestPair("Abigail made this <  abigail   @   example  .    com    >", true),
        new TestPair("Abigail(the bitch)@example.com", true),
        new TestPair("Abigail <abigail @ example . (bar) com >", true),
        new TestPair("Abigail < (one)  abigail (two) @(three)example . (bar) com (quz) >", true),
        new TestPair("Abigail (foo) (((baz)(nested) (comment)) ! ) < (one)  abigail (two) @(three)example . (bar) com (quz) >", true),
        new TestPair("Abigail <abigail(fo\\(o)@example.com>", true),
        new TestPair("Abigail <abigail(fo\\)o)@example.com> ", true),
        new TestPair("(foo) abigail@example.com", true),
        new TestPair("abigail@example.com (foo)", true),
        new TestPair("\"Abi\\\"gail\" <abigail@example.com>", true),
        new TestPair("abigail@[example.com]", true),
        new TestPair("abigail@[exa\\[ple.com]", true),
        new TestPair("abigail@[exa\\]ple.com]", true),
        new TestPair("\":sysmail\"@  Some-Group. Some-Org", true),
        new TestPair("Muhammed.(I am  the greatest) Ali @(the)Vegas.WBA", true),
        new TestPair("mailbox.sub1.sub2@this-domain", true),
        new TestPair("sub-net.mailbox@sub-domain.domain", true),
        new TestPair("name:;", true),
        new TestPair("':;", true),
        new TestPair("name:   ;", true),
        new TestPair("Alfred Neuman <Neuman@BBN-TENEXA>", true),
        new TestPair("Neuman@BBN-TENEXA", true),
        new TestPair("\"George, Ted\" <Shared@Group.Arpanet>", true),
        new TestPair("Wilt . (the  Stilt) Chamberlain@NBA.US", true),
        new TestPair("Cruisers:  Port@Portugal, Jones@SEA;", true),
        new TestPair("$@[]", true),
        new TestPair("*()@[]", true),
        new TestPair("\"quoted ( brackets\" ( a comment )@example.com", true),
        new TestPair("\"Joe & J. Harvey\"\\x0D\\x0A     <ddd\\@ Org>", true),
        new TestPair("\"Joe &\\x0D\\x0A J. Harvey\" <ddd \\@ Org>", true),
        new TestPair("Gourmets:  Pompous Person <WhoZiWhatZit\\@Cordon-Bleu>,\\x0D\\x0A" +
            "        Childs\\@WGBH.Boston, \"Galloping Gourmet\"\\@\\x0D\\x0A" +
            "        ANT.Down-Under (Australian National Television),\\x0D\\x0A" +
            "        Cheapie\\@Discount-Liquors;", true),
        new TestPair("   Just a string", false),
        new TestPair("string", false),
        new TestPair("(comment)", false),
        new TestPair("()@example.com", false),
        new TestPair("fred(&)barny@example.com", false),
        new TestPair("fred\\ barny@example.com", false),
        new TestPair("Abigail <abi gail @ example.com>", false),
        new TestPair("Abigail <abigail(fo(o)@example.com>", false),
        new TestPair("Abigail <abigail(fo)o)@example.com>", false),
        new TestPair("\"Abi\"gail\" <abigail@example.com>", false),
        new TestPair("abigail@[exa]ple.com]", false),
        new TestPair("abigail@[exa[ple.com]", false),
        new TestPair("abigail@[exaple].com]", false),
        new TestPair("abigail@", false),
        new TestPair("@example.com", false),
        new TestPair("phrase: abigail@example.com abigail@example.com ;", false),
        new TestPair("invalid�char@example.com", false)
    };

    /**
     * Write this test based on perl Mail::RFC822::Address
     * which takes its example email address directly from RFC822
     * 
     * @throws ValidatorException 
     */
    public void testEmailFromPerl() throws ValidatorException {
        ValueBean info = new ValueBean();
        for (int index = 0; index < testEmailFromPerl.length; index++) {
            info.setValue(testEmailFromPerl[index].item);
            valueTest(info, testEmailFromPerl[index].valid);
        }
    }

   /**
    * Utlity class to run a test on a value.
    *
    * @param info	Value to run test on.
    * @param passed	Whether or not the test is expected to pass.
    */
   private void valueTest(ValueBean info, boolean passed) throws ValidatorException {
      // Construct validator based on the loaded resources 
      // and the form key
      Validator validator = new Validator(resources, FORM_KEY);
      // add the name bean to the validator as a resource 
      // for the validations to be performed on.
      validator.setParameter(Validator.BEAN_PARAM, info);

      // Get results of the validation.
      ValidatorResults results = null;
      
      // throws ValidatorException, 
      // but we aren't catching for testing 
      // since no validation methods we use 
      // throw this
      results = validator.validate();
      
      assertNotNull("Results are null.", results);
      
      ValidatorResult result = results.getValidatorResult("value");

      assertNotNull(ACTION + " value ValidatorResult should not be null.", result);
      assertTrue("Value "+info.getValue()+" ValidatorResult should contain the '" + ACTION +"' action.", result.containsAction(ACTION));
      assertTrue("Value "+info.getValue()+"ValidatorResult for the '" + ACTION +"' action should have " + (passed ? "passed" : "failed") + ".", (passed ? result.isValid(ACTION) : !result.isValid(ACTION)));
    }
}                                                         