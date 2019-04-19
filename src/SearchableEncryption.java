/**
 * Created by Liuqi on 2019/4/16.
 */
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Scanner;

public class SearchableEncryption {
    
    private static String nonce = "c59bcf35";
    private static String STREAM_CIPHER_KEY = "thiskeyisverybad";
    private static String ENCRYPTION_KEY = "Sixteen byte key";
    private static String plaintext = "This is uuuuuuuu";
    
    
    public static byte[] generateStreamCipher(String key,String nonce,String counter,String target){
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key.getBytes(),"AES"),new IvParameterSpec(HexUtil.hexStr2ByteArray(nonce+counter)));
            return cipher.doFinal(target.getBytes("UTF-8"));
        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    
    public static byte[] aesEncrypt(String key,String target,String iv){
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
//            System.out.println("iv: "+iv.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key.getBytes(),"AES"),new IvParameterSpec(iv.getBytes("UTF-8")));
            return cipher.doFinal(target.getBytes("UTF-8"));
        } catch (Exception e){
            e.printStackTrace();
        }
        System.out.println("aesEncrypt error!");
        return null;
    }

    
    public static byte[] aesEncrypt(String key,byte[] target,String iv){
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
//            System.out.println("iv: "+iv.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key.getBytes(),"AES"),new IvParameterSpec(iv.getBytes("UTF-8")));
            return cipher.doFinal(target);
        } catch (Exception e){
            e.printStackTrace();
        }
        System.out.println("aesEncrypt error!");
        return null;
    }
    
    public static void encryptFile() throws IOException {
        FileUtil.deleteFiles("enc/");
        File[] files = FileUtil.getDirFiles("raw/");
        for (File file : files)  {
            String filePath = file.toString();
            String fileName = file.getName();
            String content = FileUtil.read(filePath, "UTF-8");
            List<String> words = FileUtil.getWords(content);
//            System.out.println(words);
            int count = 0;
            for(String word : words) {
                String counter = HexUtil.ljust(24,count,"0");
                byte[] streamCipher = generateStreamCipher(STREAM_CIPHER_KEY, nonce, counter, plaintext);
                String Si = HexUtil.byteArray2HexStr(streamCipher);
//                System.out.println("Si: "+Si);
                String str = word;
                for (int i = 0; i < 32-word.length();i++){
                    str = str+".";
                }
                byte[] Ewibyte = aesEncrypt(ENCRYPTION_KEY,str,plaintext);
                String Ewi = HexUtil.byteArray2HexStr(Ewibyte);
//                System.out.println("Ewi: "+Ewi);
                byte[] FiSibyte = aesEncrypt(ENCRYPTION_KEY,streamCipher,plaintext);
                String FiSi = HexUtil.byteArray2HexStr(FiSibyte);
//                System.out.println("FiSi: "+FiSi);
                String Ti = Si + FiSi;
                char[] result = HexUtil.XOR(Ewi,Ti);
                
                String writePath = "enc/"+fileName;
                FileUtil.write(new String(result),writePath,"UTF-8");
                count++;
            }
        }
        
    }
    
    public static void searchFile(String keyword) throws IOException {
        boolean flag;
        File[] files = FileUtil.getDirFiles("enc/");
        String str = keyword;
        for (int i = 0; i < 32-keyword.length();i++){
            str = str+".";
        }
        byte[] cipherKeywordbyte = aesEncrypt(ENCRYPTION_KEY,str,plaintext);
        String cipher2Search = HexUtil.byteArray2HexStr(cipherKeywordbyte);
        
        
        for (File file : files) {
            flag = false;
            String filePath = file.toString();
            String fileName = file.getName();
            String content = FileUtil.read(filePath, "UTF-8");
            String[] encWords = FileUtil.getEncWords(content);
//            System.out.println(encWords);
            for(String encWord:encWords) {
                char[] TiChar = HexUtil.XOR(cipher2Search,encWord);
                String TiStr = new String(TiChar);
                String[] Ti = new String[2];
                Ti[0] = TiStr.substring(0,TiStr.length()/2);
                Ti[1] = TiStr.substring(TiStr.length()/2);
                byte[] ti0 = aesEncrypt(ENCRYPTION_KEY,HexUtil.hexStr2ByteArray(Ti[0]),plaintext);
                String magic = HexUtil.byteArray2HexStr(ti0).toLowerCase();
                if(magic.equals(Ti[1])){
                    flag = true;
                }
            }
            if(flag)
                System.out.println(keyword+" exists in "+fileName);
            else
                System.out.println(keyword+" not exists in "+fileName);
        }
    }
    
    public static void main(String[] args) throws IOException {
        encryptFile();

        while(true) {
            System.out.print("input keyword to search: ");
            Scanner sc = new Scanner(System.in);
            String str = sc.nextLine();
            searchFile(str);
        }
    }
}
