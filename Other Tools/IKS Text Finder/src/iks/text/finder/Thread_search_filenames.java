
package iks.text.finder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JOptionPane;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.DirectoryFileFilter;
import org.apache.commons.io.filefilter.RegexFileFilter;


public class Thread_search_filenames extends Thread
{
    public boolean can_be_stopped = false;
    public int found_files_count = 0;
    public int processed_files_count = 0;
    public String actual_file = "";
    public List<String> filenames_array = new ArrayList<String>();
    public List<String> filepaths_array = new ArrayList<String>();
    
    public String text;
    public String path;
    public boolean only_five;
    
    Thread_search_filenames(String text, String path, boolean only_five)
    {
        this.text = text;
        this.path = path;
        this.only_five = only_five;
    }
    
    public void run()
    {

        Path dir = Paths.get(path);
        
        try {
                list_all_files(filenames_array, dir);
            } 
        catch (Exception ex) 
                { 
                    JOptionPane.showMessageDialog(null, "Directory is not valid!", "InfoBox", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
        
            can_be_stopped = true;


    }


        
    private List<String> list_all_files(List<String> fileNames, Path dir) 
    {
         String pattern = ".*" + text + ".*";
         Pattern r = Pattern.compile(pattern);
         Matcher m = null;
         String filename = "";
        
        try(DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) 
        {
            for (Path path : stream) 
            {
                if(path.toFile().isDirectory()) 
                {
                    list_all_files(fileNames, path);
                } 
                else 
                {
                    filename = path.getFileName().toString();
                    m = r.matcher(filename);
                    actual_file = filename;
                    processed_files_count += 1;
                    
                    while (m.find()) 
                    {
                        filenames_array.add(m.group());
                        filepaths_array.add(path.toAbsolutePath().toString());
                        //System.out.println(path.toAbsolutePath().toString());
                        found_files_count += 1;
                    }
                    
                    //fileNames.add(path.toAbsolutePath().toString());
                    //System.out.println(path.toAbsolutePath().toString());
                }
            }   
        } catch(IOException e) { /*System.out.println("Blad!");*/ }
    return fileNames;
} 
    
    
}
