import android.os.AsyncTask;
import android.os.Build;

import androidx.annotation.RequiresApi;

import java.io.PrintWriter;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.security.SecureRandom;

public class MessageSender extends AsyncTask<String, Void, Void> {
    private static final String IP = "192.168.0.135";
    private static final int PORT = 4444;

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

            // Generate a random key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128, random);
            SecretKey key = keyGenerator.generateKey();

            // Encrypt the message with the nonce and key
            byte[] encryptedMessage = encrypt(message, key, nonce);

            // Combine the nonce and the encrypted message
            byte[] combined = new byte[nonce.length + encryptedMessage.length];
            System.arraycopy(nonce, 0, combined, 0, nonce.length);
            System.arraycopy(encryptedMessage, 0, combined, nonce.length, encryptedMessage.length);

            // Send the combined message and key as a Base64-encoded string
            printWriter.write(Base64.getEncoder().encodeToString(combined) + "\n");
            printWriter.write(Base64.getEncoder().encodeToString(key.getEncoded()) + "\n");

            printWriter.flush();
            printWriter.close();
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] encrypt(String message, SecretKey key, byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(message.getBytes());
    }
}
