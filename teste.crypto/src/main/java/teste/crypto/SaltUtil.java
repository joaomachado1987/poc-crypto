package teste.crypto;

/**
 * @author Tiago Baldo
 */
public class SaltUtil {

    public static String salt(String passphrase) {
        int len = passphrase.length();
        if (len % 2 == 0) {
            return concatPass(passphrase, CypherEnum.LENGTH_1.getValue());
        } else {
            return concatPass(passphrase, CypherEnum.LENGTH_6.getValue());
        }
    }

    private static String concatPass(String pass, String key) {
        StringBuilder sb = new StringBuilder();
        sb.append(key);
        sb.append(pass);
        sb.append(key);
        return sb.toString();
    }

}
