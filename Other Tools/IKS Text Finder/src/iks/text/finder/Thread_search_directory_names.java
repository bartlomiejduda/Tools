
package iks.text.finder;



import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JOptionPane;
import org.apache.commons.io.filefilter.RegexFileFilter;



public class Thread_search_directory_names extends Thread
{
    
    public boolean can_be_stopped = false;
    public int found_directories_count = 0;
    public int processed_directories_count = 0;
    public String actual_directory = "";
    public List<String> directory_names_array = new ArrayList<String>();
    public List<String> directory_paths_array = new ArrayList<String>();
    
    public String text;
    public String path;
    public boolean only_five;
    
    Thread_search_directory_names(String text, String path)
    {
        this.text = text;
        this.path = path;
    }
    
    public void run()
    {
            Path dir = Paths.get(path);
        
        try {
                list_all_directories(directory_names_array, dir);
            } 
        catch (Exception ex) 
                { 
                    JOptionPane.showMessageDialog(null, "Directory is not valid!", "InfoBox", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
        
        
        can_be_stopped = true;
    }
    
    
    
        private List<String> list_all_directories(List<String> dirNames, Path dir) 
    {
         String pattern = ".*" + text + ".*";
         Pattern r = Pattern.compile(pattern);
         Matcher m = null;
         String dir_name = "";
        
        try(DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) 
        {
            for (Path path : stream) 
            {
                if(path.toFile().isDirectory()) 
                {
                    
                    dir_name = path.getFileName().toString();
                    //System.out.println(dir_name);
                    m = r.matcher(dir_name);
                    actual_directory = dir_name;
                    processed_directories_count += 1;
                    
                    while (m.find()) 
                    {
                        directory_names_array.add(m.group());
                        directory_paths_array.add(path.toAbsolutePath().toString());
                        found_directories_count += 1;
                    }
                    
                    
                    
                    list_all_directories(dirNames, path);
                } 
 
            }   
        } catch(IOException e) { /*System.out.println("Blad!");*/ }
    return dirNames;
} 
    
    
 
    
    
    
    
}
