import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import java.util.Base64;

public class Server {
    private static final int PORT = 12345;
    private static Set<PrintWriter> clientWriters = new HashSet<>();
    private static Map<String, String> userCredentials = new HashMap<>(); // 存储用户名和加密后的密码
    private static Map<String, PrintWriter> loggedInUsers = new HashMap<>(); // 存储已登录用户的用户名和PrintWriter
    private static Map<String, String> userRoles = new HashMap<>(); // 存储用户角色
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static SecretKey aesKey;
    private static boolean adminExists = false; // 标记是否已经存在管理员用户

    public static void main(String[] args) {
        generateRSAKeyPair();
        loadUserCredentials();
        generateAESKey();

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("服务器已启动，等待客户端连接...");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("新客户端已连接: " + clientSocket.getInetAddress().getHostAddress());
                new Thread(new ClientHandler(clientSocket)).start();
            }
        } catch (IOException e) {
            System.err.println("服务器异常: " + e.getMessage());
        }
    }

    private static void generateRSAKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static void generateAESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            aesKey = keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static void loadUserCredentials() {
        try (BufferedReader reader = new BufferedReader(new FileReader("1.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":");
                if (parts.length == 3) {
                    userCredentials.put(parts[0], parts[1]);
                    userRoles.put(parts[0], parts[2]);
                    if (parts[2].equals("admin")) {
                        adminExists = true;
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void saveUserCredentials(String username, String encryptedPassword, String role) {
        try (PrintWriter writer = new PrintWriter(new FileWriter("1.txt", true))) {
            writer.println(username + ":" + encryptedPassword + ":" + role);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String decryptRSA(String encryptedText, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static class ClientHandler implements Runnable {
        private Socket socket;
        private PrintWriter out;
        private BufferedReader in;
        private String username;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try {
                out = new PrintWriter(socket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));

                synchronized (clientWriters) {
                    clientWriters.add(out);
                }

                // 发送公钥给客户端
                out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
                // 发送AES密钥给客户端
                out.println(Base64.getEncoder().encodeToString(aesKey.getEncoded()));

                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    System.out.println("收到消息: " + inputLine);
                    handleMessage(inputLine);
                }
            } catch (IOException e) {
                System.err.println("客户端处理异常: " + e.getMessage());
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    System.err.println("关闭套接字异常: " + e.getMessage());
                }
                synchronized (clientWriters) {
                    clientWriters.remove(out);
                }
                if (username != null) {
                    loggedInUsers.remove(username);
                }
            }
        }

        private void handleMessage(String message) {
            if (message.startsWith("LOGIN ")) {
                String[] parts = message.split(" ");
                if (parts.length == 3) {
                    String username = parts[1];
                    String encryptedPassword = parts[2];
                    if (userCredentials.containsKey(username)) {
                        if (loggedInUsers.containsKey(username)) {
                            out.println("登录失败，账号已在其他地方登录，请修改密码后重新登录。");
                            try {
                                socket.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        } else {
                            String decryptedPassword = decryptRSA(encryptedPassword, privateKey);
                            if (decryptedPassword != null && decryptedPassword.equals(userCredentials.get(username))) {
                                loggedInUsers.put(username, out);
                                this.username = username;
                                out.println("登录成功");
                            } else {
                                out.println("登录失败，用户名或密码错误");
                            }
                        }
                    } else {
                        out.println("登录失败，用户名或密码错误");
                    }
                }
            } else if (message.startsWith("REGISTER ")) {
                String[] parts = message.split(" ");
                if (parts.length == 4) {
                    String username = parts[1];
                    String encryptedPassword = parts[2];
                    String role = parts[3];
                    if (!userCredentials.containsKey(username)) {
                        if (role.equals("admin") && adminExists) {
                            out.println("注册失败，管理员用户已存在");
                        } else if (role.equals("sub_admin") || role.equals("channel_admin")) {
                            out.println("注册失败，不允许注册次管理员或子频道管理员用户");
                        } else {
                            String decryptedPassword = decryptRSA(encryptedPassword, privateKey);
                            if (decryptedPassword != null) {
                                userCredentials.put(username, decryptedPassword);
                                userRoles.put(username, role);
                                saveUserCredentials(username, decryptedPassword, role);
                                if (role.equals("admin")) {
                                    adminExists = true;
                                }
                                out.println("注册成功");
                            } else {
                                out.println("注册失败，解密错误");
                            }
                        }
                    } else {
                        out.println("注册失败，用户名已存在");
                    }
                }
            } else if (message.startsWith("CHANGE_PASSWORD ")) {
                String[] parts = message.split(" ");
                if (parts.length == 4) {
                    String username = parts[1];
                    String oldEncryptedPassword = parts[2];
                    String newEncryptedPassword = parts[3];
                    if (userCredentials.containsKey(username)) {
                        String decryptedOldPassword = decryptRSA(oldEncryptedPassword, privateKey);
                        if (decryptedOldPassword != null && decryptedOldPassword.equals(userCredentials.get(username))) {
                            String decryptedNewPassword = decryptRSA(newEncryptedPassword, privateKey);
                            if (decryptedNewPassword != null) {
                                userCredentials.put(username, decryptedNewPassword);
                                saveUserCredentials(username, decryptedNewPassword, userRoles.get(username));
                                out.println("密码修改成功");
                            } else {
                                out.println("密码修改失败，解密错误");
                            }
                        } else {
                            out.println("密码修改失败，旧密码错误");
                        }
                    } else {
                        out.println("密码修改失败，用户名不存在");
                    }
                }
            } else if (message.startsWith("EDIT_USER ")) {
                if (username != null) {
                    String[] parts = message.split(" ");
                    if (parts.length == 4) {
                        String targetUsername = parts[1];
                        String newEncryptedPassword = parts[2];
                        String newRole = parts[3];
                        String role = userRoles.get(username);
                        if (role != null && role.equals("admin")) {
                            editUser(targetUsername, newEncryptedPassword, newRole);
                        } else {
                            out.println("权限不足");
                        }
                    }
                } else {
                    out.println("请先登录");
                }
            } else if (message.startsWith("!send ")) {
                if (username != null) {
                    String[] parts = message.split(" ", 3);
                    if (parts.length == 3) {
                        String recipient = parts[1];
                        String encryptedMessage = parts[2];
                        if (loggedInUsers.containsKey(recipient)) {
                            PrintWriter recipientWriter = loggedInUsers.get(recipient);
                            recipientWriter.println("PRIVATE " + username + " " + encryptedMessage);
                            saveMessage(encryptedMessage, hashMessage(encryptedMessage));
                        } else {
                            out.println("用户不在线");
                        }
                    }
                } else {
                    out.println("请先登录");
                }
            } else if (message.startsWith("!sendfile ")) {
                if (username != null) {
                    String[] parts = message.split(" ", 3);
                    if (parts.length == 3) {
                        String recipient = parts[1];
                        String encryptedFile = parts[2];
                        if (loggedInUsers.containsKey(recipient)) {
                            PrintWriter recipientWriter = loggedInUsers.get(recipient);
                            recipientWriter.println("FILE " + encryptedFile);
                        } else {
                            out.println("用户不在线");
                        }
                    }
                } else {
                    out.println("请先登录");
                }
            } else {
                out.println("未知命令");
            }
        }

        private void editUser(String targetUsername, String newEncryptedPassword, String newRole) {
            String decryptedNewPassword = decryptRSA(newEncryptedPassword, privateKey);
            if (decryptedNewPassword != null) {
                userCredentials.put(targetUsername, decryptedNewPassword);
                userRoles.put(targetUsername, newRole);
                saveUserCredentials(targetUsername, decryptedNewPassword, newRole);
                out.println("用户编辑成功");
            } else {
                out.println("用户编辑失败，解密错误");
            }
        }

        private void saveMessage(String encryptedMessage, String hash) {
            try (PrintWriter writer = new PrintWriter(new FileWriter("chat_log.txt", true))) {
                writer.println(encryptedMessage + ":" + hash);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        private String hashMessage(String message) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hashBytes = md.digest(message.getBytes("UTF-8"));
                return Base64.getEncoder().encodeToString(hashBytes);
            } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            return null;
        }
    }
}
