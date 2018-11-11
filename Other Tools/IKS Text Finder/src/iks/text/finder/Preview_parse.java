
package iks.text.finder;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;


public class Preview_parse 
{
    public static String Parse(String text)
    {
        String parsed_text = text;
        List<Integer> positions = new ArrayList<Integer>();
        
        int index = text.indexOf("{");
        while (index >= 0) 
        {
            positions.add(index);
            index = text.indexOf("{", index + 1);
        }
        
        
        
        String s = "";
        for (int pos : positions)
        {
            if (text.length() > pos+3)
            {
                s = text.substring(pos+1, pos+3);
                //System.out.println("ZZZ: " + s);
            
                if (s.matches("-?[0-9a-fA-F]+"))
                {
                    parsed_text = parsed_text.replace("{" + s + "}", hexToAscii(s));
                    //System.out.println("Zamieniam: " + s);
                }
            
            }
        }
        
        //System.out.println(parsed_text);
        return parsed_text;
    }
    
    public static String hexToAscii(String hexStr) {
    StringBuilder output = new StringBuilder("");
     
    for (int i = 0; i < hexStr.length(); i += 2) {
        String str = hexStr.substring(i, i + 2);
        output.append((char) Integer.parseInt(str, 16));
    }
     
    return output.toString();
}
}
