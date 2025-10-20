package Neet.Royall;

import android.content.Context;
import android.util.Base64;
import android.app.Activity;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;
import java.io.InputStream;

public class AES {

    private static final String DefaultKEY = " Cleaner@Royall#6278 ";
    public static final String ENCRYPT = "encrypt", DECRYPT = "decrypt";

    public static String getValue(Context c, String f, String m, String k) {
     try (InputStream i = c.getAssets().open(f.charAt(0) == '/' ? f.substring(1) : f)) {
        byte[] b = new byte[i.available()]; i.read(b);
        String s = new String(b);
        return "SECURE".equals(m) ? DecryptRun(s, (k == null || k.isEmpty()) ? DefaultKEY : k) : s;
     } catch (Exception e) {
        return e.getMessage();
     }
    }


    public static String DecryptRun(String t, String k) {
     try {
        return t.startsWith("$IV")
            ? RandomRun(t, k, DECRYPT)
            : StaticRun(t, k, DECRYPT);
     } catch (Exception e) {
        return e.getMessage();
     }
    }



    public static void RandomAES(String i, String k, String act, ResultCallback cb) {
        String out;
        try {
            out = RandomRun(i, k, act);
        } catch (Exception e) {
            if (cb != null) cb.onError(e.getMessage());
            return;
        }
        if (cb != null) cb.onResult(out);
    }

    public static void StaticAES(String i, String k, String act, ResultCallback cb) {
        String out;
        try {
            out = StaticRun(i, k, act);
        } catch (Exception e) {
            if (cb != null) cb.onError(e.getMessage());
            return;
        }
        if (cb != null) cb.onResult(out);
    }


    private static SecretKey genKey(String k) throws Exception {
        return new SecretKeySpec(java.security.MessageDigest.getInstance("SHA-256").digest(k.getBytes(StandardCharsets.UTF_8)), "AES");
    }


   public static String RandomRun(String text, String key, String action) throws Exception {
    boolean isEncrypt = ENCRYPT.equals(action);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    SecretKey skey = genKey(key);

    if (isEncrypt) {
        byte[] iv = new byte[16];
        new java.security.SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, skey, new IvParameterSpec(iv));
        byte[] enc = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
        byte[] comb = new byte[16 + enc.length];
        System.arraycopy(iv, 0, comb, 0, 16);
        System.arraycopy(enc, 0, comb, 16, enc.length);
        return "$IV" + Base64.encodeToString(comb, Base64.DEFAULT);
    } else {
        if (!text.startsWith("$IV")) throw new IllegalArgumentException("Invalid encrypted format");
        byte[] raw = Base64.decode(text.substring(3), Base64.DEFAULT);
        byte[] iv = Arrays.copyOfRange(raw, 0, 16);
        byte[] enc = Arrays.copyOfRange(raw, 16, raw.length);
        cipher.init(Cipher.DECRYPT_MODE, skey, new IvParameterSpec(iv));
        byte[] res = cipher.doFinal(enc);
        return new String(res, StandardCharsets.UTF_8);
    }
   }

    public static String StaticRun(String input, String key, String action) throws Exception {
        boolean isEncrypt = ENCRYPT.equals(action);
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, genKey(key));
        byte[] data = isEncrypt ? input.getBytes(StandardCharsets.UTF_8) : Base64.decode(input, Base64.DEFAULT);
        byte[] result = c.doFinal(data);
        return isEncrypt ? Base64.encodeToString(result, Base64.DEFAULT) : new String(result, StandardCharsets.UTF_8);
    }

    public interface ResultCallback {
        void onResult(String result);
        void onError(String error);
    }


}
