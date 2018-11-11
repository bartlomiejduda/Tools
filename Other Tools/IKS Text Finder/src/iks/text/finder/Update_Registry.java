
package iks.text.finder;

import java.awt.Desktop;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;


public class Update_Registry 
{
    public String curr_path;
    String curr_jar_path;
    public String reg_script_body = "";
    public String bat_script_body = "";
    
    Update_Registry()
    {
        
        curr_path = new File(".").getAbsolutePath();
        curr_path = curr_path.substring(0, curr_path.length()-1);
        curr_jar_path = curr_path + "IKS_Text_Finder.jar";
        
        
        System.out.println(curr_path);
        System.out.println(curr_jar_path);
        
        write_reg_script();
        write_bat_script();
        run_update();
    }
    
    
    public void w_reg(String line)
    {
        reg_script_body += line + '\n';
    }
    
    public void write_reg_script()
    {
        w_reg("Windows Registry Editor Version 5.00");
        w_reg("");
        w_reg("[HKEY_CLASSES_ROOT\\Directory\\shell\\Run IKS Text Finder]");
        w_reg("@=\"&Run IKS Text Finder here\"");
        w_reg("\"Icon\"=\"%SystemRoot%\\\\System32\\\\shell32.dll,71\"");
        w_reg("");
        w_reg("[HKEY_CLASSES_ROOT\\Directory\\shell\\Run IKS Text Finder\\command]");
        w_reg("@=\"\\\\" + curr_path.replace("\\", "\\\\") + "script.bat" + "\\\" \\\"%CD%\\\"\"");
        w_reg("@=\"" + curr_path.replace("\\", "\\\\") + "script.bat" + " \\\"%V%\\\"\"");
        
    }
    
    public void w_bat(String line)
    {
        bat_script_body += line + '\n';
    }
    
    public void write_bat_script()
    {
        w_bat("start javaw -jar \"" + curr_jar_path + "\"" + " %*");
    }
    
    
    public void run_update()
    {
        try {
            
            File r = new File(curr_path + "script.reg");
            PrintWriter writer = new PrintWriter(r, "UTF-8");
            writer.println(reg_script_body);
            writer.close();
            
            File b = new File(curr_path + "script.bat");
            writer = new PrintWriter(b, "UTF-8");
            writer.println(bat_script_body);
            writer.close();
            
            Desktop.getDesktop().open(r);

        } catch (IOException ex) { System.out.println("Operation cancelled by user!"); }
    }
}
