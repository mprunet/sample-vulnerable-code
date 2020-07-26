package org.owasp.psafix.top10.vulnerable;

import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class A2Authentication {
    private final Logger LOGGER = Logger.getLogger("auth");

    AuthRepository authRepository;

    public boolean authenticate(String username, String password) {
        boolean auth=true;
        try {

            String dbPassword = authRepository.getPassword(username);
            auth = password.equals(dbPassword);
        } catch(SQLException ex) {
            LOGGER.log(Level.WARNING, "Impossible to authenticate " + username, ex);
        }
        return auth;
    }
}
