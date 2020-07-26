package org.owasp.psafix.top10.vulnerable;

import java.sql.SQLException;

public interface AuthRepository {
    String getPassword(String username) throws SQLException;
}
