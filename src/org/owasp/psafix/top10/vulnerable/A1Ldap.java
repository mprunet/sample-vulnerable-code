package org.owasp.psafix.top10.vulnerable;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.Hashtable;

/**
 * Source : https://wiki.sei.cmu.edu/confluence/spaces/flyingpdf/pdfpageexport.action?pageId=88487534
 */
// String userSN = "S*"; // Invalid
// String userPassword = "*";
// Invalid
public class A1Ldap {
    private void searchRecord(String userSN, String userPassword) throws NamingException {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        try {
            DirContext dctx = new InitialDirContext(env);
            SearchControls sc = new SearchControls();
            String[] attributeFilter = {"cn", "mail"};
            sc.setReturningAttributes(attributeFilter);
            sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
            String base = "dc=example,dc=com";
// The following resolves to (&(sn=S*)(userPassword=*))
            String filter = "(&(sn=" + userSN + ")(userPassword=" + userPassword + "))";
            NamingEnumeration<?> results = dctx.search(base, filter, sc);
            while (results.hasMore()) {
                SearchResult sr = (SearchResult) results.next();
                Attributes attrs = (Attributes) sr.getAttributes();
                Attribute attr = (Attribute) attrs.get("cn");
                System.out.println(attr);
                attr = (Attribute) attrs.get("mail");
                System.out.println(attr);
            }
            dctx.close();
        } catch (NamingException e) {
// Forward to handler
        }
    }
}