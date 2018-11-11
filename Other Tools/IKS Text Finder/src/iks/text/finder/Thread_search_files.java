
package iks.text.finder;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JOptionPane;
import javax.swing.Timer;
import org.riversun.bigdoc.bin.BigFileSearcher;
import org.riversun.bigdoc.bin.BigFileSearcher.OnProgressListener;
import org.riversun.bigdoc.bin.BigFileSearcher.OnRealtimeResultListener;


public class Thread_search_files extends Thread
{
        public boolean can_be_stopped = false;
    public int found_files_count = 0;
    public int processed_files_count = 0;
    public String actual_file = "";
    public List<String> filenames_array = new ArrayList<String>();
    public List<String> filepaths_array = new ArrayList<String>();
    public List<String> text_preview = new ArrayList<String>();
    public List<String> file_arr = new ArrayList<String>();
    public List<String> offset_arr = new ArrayList<String>();
    public long f_size;
    public float progress_percent;
    
    //public String text;
    byte[] text_b;
    public String path;
    public boolean only_five;
    
    Thread_search_files(byte[] text_b, String path, boolean only_five)
    {
        this.text_b = text_b;
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
                    ex.printStackTrace();
                    JOptionPane.showMessageDialog(null, "Directory is not valid!", "InfoBox", JOptionPane.INFORMATION_MESSAGE);
                    return;
                }
        
            can_be_stopped = true;
    }
    
    
    
    
    
        
    private List<String> list_all_files(List<String> fileNames, Path dir) 
    {
         //String pattern = ".*" + text + ".*";
         //Pattern r = Pattern.compile(pattern);
         //Matcher m = null;
         String filename = "";
         String filepath = "";
         boolean found = false;
        
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
                    filepath = path.toString();
                    actual_file = filename;
                    processed_files_count += 1;
                    
        
           byte[] my_pattern = text_b;        
           File file = new File(filepath);
           f_size = file.length();
           byte[] result = null;
           /*InputStream input =  new BufferedInputStream(new FileInputStream(file));

           KMPMatch kmp = new KMPMatch();
           int offset = kmp.indexOf(result, my_pattern);*/
//List<Long> findList = searcher.searchBigFile(file, my_pattern);



		BigFileSearcher searcher = new BigFileSearcher();
                List<Long> findList = new ArrayList<Long>();
                float progress = 0;
                


                searcher.setUseOptimization(true);

               findList = searcher.searchBigFile(file, my_pattern, new OnProgressListener() 
               {

			@Override
			public void onProgress(float progress) 
                        {
				//System.out.println("[" + file.getName() + "]" + " progress " + (int) (progress * 100f) + "% done");
                                progress_percent = progress * 100f;
			} 
                });


                for (long off : findList)
                {
                    found_files_count += 1;
                    file_arr.add(filepath);
                    offset_arr.add(Integer.toString((int)off));

                    int size = 5 + text_b.length + 5;
                    byte[] preview_arr = new byte[size];

                    DataInputStream dis = new DataInputStream(new FileInputStream(file));
                    dis.skip((int)off-5);
                    dis.read(preview_arr, 0, size);
                    text_preview.add(new String(preview_arr));
                    dis.close();
                }
           

            }
                
                
                
                
                
                
            }   
        } catch(IOException e) { /*System.out.println("Blad!");*/ }
    return fileNames;
} 
    
    
    
    


           
    public static int convert_hex(int n) 
    {
        return Integer.valueOf(String.valueOf(n), 16);
    }
        
    
    public static byte[] readAndClose(InputStream aInput)
    {
        byte[] bucket = new byte[32*1024]; 
        ByteArrayOutputStream result = null; 
        try  {
            try {
                    result = new ByteArrayOutputStream(bucket.length);
                    int bytesRead = 0;
                    while(bytesRead != -1)
                    {
                        bytesRead = aInput.read(bucket);
                        if(bytesRead > 0)
                        {
                            result.write(bucket, 0, bytesRead);
                        }
                    }
                }
      finally {
        aInput.close();

              }
            }
            catch (IOException ex){ }
        return result.toByteArray();
    }
    
    
    public static int getFilesCount(File file) 
    {
        File[] files = file.listFiles();
        int count = 0;
        for (File f : files)
            if (f.isDirectory())
                count += getFilesCount(f);
            else
                count++;

        return count;
}
    
    
    
    
    
    
    
    
    
    
}
