import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;
import java.util.Base64;

public class client {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 12345;
    private static PublicKey publicKey;
    private static SecretKey aesKey;

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
             BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in, "UTF-8"))) {

            System.out.println("已连接到服务器");

            // 获取服务器的公钥
            publicKey = getServerPublicKey(in);

            // 获取服务器的AES密钥
            aesKey = getServerAESKey(in);

            // 启动一个线程来接收服务器消息
            new Thread(() -> {
                String serverMessage;
                try {
                    while ((serverMessage = in.readLine()) != null) {
                        handleServerMessage(serverMessage);
                    }
                } catch (IOException e) {
                    System.err.println("读取服务器消息异常: " + e.getMessage());
                }
            }).start();

            // 登录或注册
            System.out.println("请输入命令（login/register/change_password/edit_user）：");
            String userInput;
            while ((userInput = stdIn.readLine()) != null) {
                if (userInput.startsWith("login ")) {
                    String[] parts = userInput.split(" ");
                    if (parts.length == 3) {
                        String encryptedPassword = encryptRSA(parts[2], publicKey);
                        out.println("LOGIN " + parts[1] + " " + encryptedPassword);
                    } else {
                        System.out.println("登录格式错误，请使用 'login 用户名 密码' 格式");
                    }
                } else if (userInput.startsWith("register ")) {
                    String[] parts = userInput.split(" ");
                    if (parts.length == 4) {
                        String encryptedPassword = encryptRSA(parts[2], publicKey);
                        out.println("REGISTER " + parts[1] + " " + encryptedPassword + " " + parts[3]);
                    } else {
                        System.out.println("注册格式错误，请使用 'register 用户名 密码 角色' 格式");
                    }
                } else if (userInput.startsWith("change_password ")) {
                    String[] parts = userInput.split(" ");
                    if (parts.length == 4) {
                        String encryptedOldPassword = encryptRSA(parts[2], publicKey);
                        String encryptedNewPassword = encryptRSA(parts[3], publicKey);
                        out.println("CHANGE_PASSWORD " + parts[1] + " " + encryptedOldPassword + " " + encryptedNewPassword);
                    } else {
                        System.out.println("修改密码格式错误，请使用 'change_password 用户名 旧密码 新密码' 格式");
                    }
                } else if (userInput.startsWith("edit_user ")) {
                    String[] parts = userInput.split(" ");
                    if (parts.length == 4) {
                        String encryptedPassword = encryptRSA(parts[2], publicKey);
                        out.println("EDIT_USER " + parts[1] + " " + encryptedPassword + " " + parts[3]);
                    } else {
                        System.out.println("编辑用户格式错误，请使用 'edit_user 用户名 新密码 新角色' 格式");
                    }
                } else if (userInput.startsWith("!send ")) {
                    String[] parts = userInput.split(" ", 3);
                    if (parts.length == 3) {
                        String recipient = parts[1];
                        String message = parts[2];
                        String encryptedMessage = encryptAES(message, aesKey);
                        String hash = hashMessage(encryptedMessage);
                        saveMessage(encryptedMessage, hash);
                        out.println("!send " + recipient + " " + encryptedMessage);
                    } else {
                        System.out.println("发送消息格式错误，请使用 '!send 用户名 消息' 格式");
                    }
                } else if (userInput.startsWith("!sendfile ")) {
                    String[] parts = userInput.split(" ", 3);
                    if (parts.length == 3) {
                        String recipient = parts[1];
                        String filePath = parts[2];
                        sendFile(recipient, filePath, out);
                    } else {
                        System.out.println("发送文件格式错误，请使用 '!sendfile 用户名 文件路径' 格式");
                    }
                } else {
                    out.println(userInput);
                }
            }
        } catch (UnknownHostException e) {
            System.err.println("未知主机: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("I/O异常: " + e.getMessage());
        }
    }

    private static PublicKey getServerPublicKey(BufferedReader in) throws IOException {
        String publicKeyBase64 = in.readLine();
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            return keyFactory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static SecretKey getServerAESKey(BufferedReader in) throws IOException {
        String aesKeyBase64 = in.readLine();
        byte[] aesKeyBytes = Base64.getDecoder().decode(aesKeyBase64);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    private static String encryptRSA(String plainText, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String encryptAES(String plainText, SecretKey secretKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String hashMessage(String message) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(message.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("SHA-256 algorithm not found", e);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new RuntimeException("UTF-8 encoding not supported", e);
        }
    }

    private static void saveMessage(String encryptedMessage, String hash) {
        try (PrintWriter writer = new PrintWriter(new FileWriter("chat_log.txt", true))) {
            writer.println(encryptedMessage + ":" + hash);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void handleServerMessage(String message) {
        if (message.startsWith("PRIVATE ")) {
            String[] parts = message.split(" ", 3);
            if (parts.length == 3) {
                String sender = parts[1];
                String encryptedMessage = parts[2];
                String decryptedMessage = decryptAES(encryptedMessage, aesKey);
                System.out.println("私聊消息 from " + sender + ": " + decryptedMessage);
            }
        } else if (message.startsWith("FILE ")) {
            String[] parts = message.split(" ", 2);
            if (parts.length == 2) {
                String encryptedFile = parts[1];
                String decryptedFile = decryptAES(encryptedFile, aesKey);
                saveFile(decryptedFile);
            }
        } else {
            System.out.println("服务器: " + message);
        }
    }

    private static String decryptAES(String encryptedText, SecretKey secretKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static void sendFile(String recipient, String filePath, PrintWriter out) {
        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            System.err.println("文件不存在或不是文件: " + filePath);
            return;
        }

        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] fileBytes = new byte[(int) file.length()];
            fis.read(fileBytes);
            String encryptedFile = encryptAES(Base64.getEncoder().encodeToString(fileBytes), aesKey);
            out.println("!sendfile " + recipient + " " + encryptedFile);
        } catch (IOException e) {
            System.err.println("发送文件时发生错误: " + e.getMessage());
        }
    }

    private static void saveFile(String fileData) {
        try {
            byte[] fileBytes = Base64.getDecoder().decode(fileData);
            try (FileOutputStream fos = new FileOutputStream("received_file.txt")) {
                fos.write(fileBytes);
            }
            System.out.println("文件已保存为 received_file.txt");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
