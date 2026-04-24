// This file intentionally contains security vulnerabilities for testing purposes.
// DO NOT use any of the patterns below in production code.

import java.io.*;
import java.security.*;
import java.sql.*;
import java.util.Random;

public class VulnerableApp {

    // CWE-259: Hardcoded credential
    private static final String password = "admin123";
    private static final String apiKey = "sk-secret-api-key-12345";

    // CWE-89: SQL injection via string concatenation
    public void getUser(Connection conn, String username) throws SQLException {
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + username + "'");
    }

    // CWE-78: OS command injection
    public void runCommand(String userInput) throws IOException {
        Runtime.getRuntime().exec("ls " + userInput);
        new ProcessBuilder("sh", userInput + " -c");
    }

    // CWE-502: Insecure deserialization
    public Object deserialize(InputStream is) throws Exception {
        return new ObjectInputStream(is).readObject();
    }

    // CWE-327: Weak cryptographic hash
    public byte[] hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }

    public byte[] hashPasswordSha1(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(password.getBytes());
    }

    // CWE-338: Insecure random
    public int generateToken() {
        return new Random().nextInt(1_000_000);
    }

    // CWE-209: Stack trace exposure
    public void riskyOperation() {
        try {
            throw new RuntimeException("error");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // CWE-611: XXE risk
    public void parseXml() throws Exception {
        javax.xml.parsers.DocumentBuilderFactory factory =
            javax.xml.parsers.DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder();
    }
}
