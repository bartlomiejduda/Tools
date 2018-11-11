
package iks.text.finder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;


public class Binary_parse 
{
    public static byte[] Parse(String text)
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        List<Integer> positions = new ArrayList<Integer>();
        
        int index = text.indexOf("{");
        while (index >= 0) 
        {
            positions.add(index);
            index = text.indexOf("{", index + 1);
        }
        
        for (int i = 0; i < text.length(); i++)
        {
            char ch = text.charAt(i);      
            
            if (ch != '{')
            {
                try {
                    out.write(char_to_byte_array(ch));
                } catch (IOException ex) {ex.printStackTrace();}
            }
            else
            {
                String hex_str = text.substring(i+1, i+3);
                try {
                    out.write(hex_str_to_byte_array(hex_str));
                } catch (IOException ex) {ex.printStackTrace();}
                i += 3;
            }
            
            
        }
        
        String s = "";
 

        
        byte[] result_string = out.toByteArray();
        return result_string;
    }
    
    //insert special
    public static String byte_array_to_string(byte[] input)
    {
        String result = "";
        for(byte b : input)
        {
            byte[] bb = new byte[]{b};
            result += "{" + bytes_to_hex(bb) + "}";
        }
        
        return result;
    }
    
    

    public static String bytes_to_hex(byte[] in) 
    {
        final StringBuilder builder = new StringBuilder();
        for(byte b : in) 
        {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }


    
    
    
    public static byte[] hex_str_to_byte_array(String s) 
    {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) 
        {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
            + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    
    
    
 public static byte[] char_to_byte_array(char c)
 {
     char[] ch = new char[]{c};
     byte [] b_arr = new String(ch).getBytes(StandardCharsets.US_ASCII);
     return b_arr;
 }
    

}
