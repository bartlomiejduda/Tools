
package iks.text.finder;

import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import javax.swing.JButton;
import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.Timer;
import net.miginfocom.swing.MigLayout;


public class Progress_Window extends JFrame
{
    int sec_counter = 0;
    
    public String mode;
    public String text;
    public byte[] text_b;
    public String search_dir_path;
    public boolean is_checked_only_five;
    public boolean is_checked_size_matters;
    
    Progress_Window(String mode, String text, String search_dir_path, boolean is_checked_only_five, boolean is_checked_size_matters)
    {
        this.mode = mode;
        this.text = text;
        this.search_dir_path = search_dir_path;
        this.is_checked_only_five = is_checked_only_five;
        this.is_checked_size_matters = is_checked_size_matters;
        run_progress_window();
    }
    
    Progress_Window(String mode, byte[] text_b, String search_dir_path, boolean is_checked_only_five, boolean is_checked_size_matters)
    {
        this.mode = mode;
        this.text_b = text_b;
        this.text = Preview_parse.Parse(Binary_parse.byte_array_to_string(text_b));
        this.search_dir_path = search_dir_path;
        this.is_checked_only_five = is_checked_only_five;
        this.is_checked_size_matters = is_checked_size_matters;
        run_progress_window();
    }
    
    
    public void run_progress_window()
    {
        this.setSize(420, 350);
        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        this.setTitle("Progress");
        this.setResizable(false);
        this.setLocationRelativeTo(null);
        JPanel panel = new JPanel(new MigLayout("gap 0 0, , hidemode 2"));
        
        
        

        
        
        JLabel text_lab = new JLabel();
        panel.add(text_lab, "pos 20 40, h 30, w 900");
        text_lab.setText("Text to search: " + text);
        Font f = text_lab.getFont();
        text_lab.setFont(f.deriveFont(f.getStyle() & ~Font.BOLD));
        
        JEditorPane status_lab = new JEditorPane();
        status_lab.setContentType("text/html");
        status_lab.setText("Status:  <font color=\"orange\">Running</font> ");
        panel.add(status_lab, "pos 20 20, h 30, w 900");
        status_lab.setFont(f.deriveFont(f.getStyle() & ~Font.BOLD));
        status_lab.setBorder(null);
        status_lab.setBackground(null);
        status_lab.setEditable(false);
        
        JLabel time_elapsed_lab = new JLabel();
        panel.add(time_elapsed_lab, "pos 20 70, h 30, w 900");
        time_elapsed_lab.setText("Time elapsed: 00:00:00");
        time_elapsed_lab.setFont(f.deriveFont(f.getStyle() & ~Font.BOLD));
        
        JTextArea processed_file = new JTextArea();
        panel.add(processed_file, "pos 20 100, h 30, w 380");
        
        if (mode == "mode2")
        {
            processed_file.setText("Actually processed directory: ");
        }
        else
        {
            processed_file.setText("Actually processed file: ");
        }
        
        
        processed_file.setLineWrap(true);
        processed_file.setWrapStyleWord(true);
        processed_file.setEditable(false);
        processed_file.setBackground(null); 
        processed_file.setBorder(null); 
        
        JLabel found_lab = new JLabel();
        panel.add(found_lab, "pos 20 140, h 30, w 900");
        found_lab.setText("Found items: 0");
        found_lab.setFont(f.deriveFont(f.getStyle() & ~Font.BOLD));
        
        JLabel processed_lab = new JLabel();
        panel.add(processed_lab, "pos 20 160, h 30, w 900");
        processed_lab.setText("Processed items: 0");
        processed_lab.setFont(f.deriveFont(f.getStyle() & ~Font.BOLD));


ActionListener actionListener = new ActionListener() 
    {
        public void actionPerformed(ActionEvent actionEvent) 
        {
            sec_counter += 1;
            time_elapsed_lab.setText("Time elapsed: " + seconds_to_time(sec_counter));
        }
    };
    Timer timer = new Timer(1000, actionListener);
    timer.start();


        JButton pause_b = new JButton();
        panel.add(pause_b, "pos 20 190, h 30, w 70");
        pause_b.setText("Pause");
        

        
        
        JButton abort_b = new JButton();
        panel.add(abort_b, "pos 110 190, h 30, w 70");
        abort_b.setText("Abort");
        

        
        this.add(panel);
        this.setVisible(true);
        
        Thread_search_filenames search_filenames = new Thread_search_filenames(text, search_dir_path, is_checked_only_five);
        Thread_search_directory_names search_dir = new Thread_search_directory_names(text, search_dir_path);
        Thread_search_files search_files = new Thread_search_files(text_b, search_dir_path, is_checked_only_five);
        
        
        if (mode == "mode1")
        {
            search_filenames.start();
        }
        else if (mode == "mode2")
        {
            search_dir.start();
        }
        else if (mode == "mode3")
        {
            search_files.start();
        }



        final Timer timer2 = new Timer(200, null);

       ActionListener timer3_actionListener = new ActionListener() 
    {
        public void actionPerformed(ActionEvent actionEvent) 
        {

            
            if (mode == "mode1")
            {
                processed_file.setText("Actually processed file: " + search_filenames.actual_file);
                found_lab.setText("Found items: " + search_filenames.found_files_count);
                processed_lab.setText("Processed items: " + search_filenames.processed_files_count);
            }
            else if (mode == "mode2")
            {
                processed_file.setText("Actually processed directory: " + search_dir.actual_directory);
                found_lab.setText("Found items: " + search_dir.found_directories_count);
                processed_lab.setText("Processed items: " + search_dir.processed_directories_count);
            }
            else if (mode == "mode3")
            {
                if (search_files.f_size < 1024*1024*10)
                    processed_file.setText("Actually processed file: " + search_files.actual_file);
                else
                    processed_file.setText("Actually processed file: " + search_files.actual_file + "(" + String.format("%.2f", search_files.progress_percent) + "%)");
                found_lab.setText("Found items: " + search_files.found_files_count);
                processed_lab.setText("Processed items: " + search_files.processed_files_count);
            }
            
            
            if (search_files.can_be_stopped == true)
            {
                search_files.interrupt();
                timer.stop();
                timer2.stop();

                status_lab.setText("Status:  <font color=\"green\">Finished</font> ");
                pause_b.setEnabled(false);
                abort_b.setText("Close");
                Result_Window res_wind = new Result_Window(search_files.file_arr, search_files.filepaths_array, search_files.offset_arr, search_files.text_preview, "mode3");
            }
            
            
            if (search_dir.can_be_stopped == true)
            {
                search_dir.interrupt();
                timer.stop();
                timer2.stop();

                status_lab.setText("Status:  <font color=\"green\">Finished</font> ");
                pause_b.setEnabled(false);
                abort_b.setText("Close");
                Result_Window res_wind = new Result_Window(search_dir.directory_names_array, search_dir.directory_paths_array, "mode2");
            }
                
            if (search_filenames.can_be_stopped == true)
            {
                search_filenames.interrupt();
                timer.stop();
                timer2.stop();

                status_lab.setText("Status:  <font color=\"green\">Finished</font> ");
                pause_b.setEnabled(false);
                abort_b.setText("Close");
                Result_Window res_wind = new Result_Window(search_filenames.filenames_array, search_filenames.filepaths_array, "mode1");
            }
        }
    };
     timer.addActionListener(timer3_actionListener);
        
    timer2.start(); 
    
    
            abort_b.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                
                search_filenames.interrupt();
                search_dir.interrupt();
                timer.stop();
                timer2.stop();
                dispose();
                
                 if (!status_lab.getText().contains("Finished"))
                {
                
                    if (mode == "mode1")
                    {
                        Result_Window res_wind = new Result_Window(search_filenames.filenames_array, search_filenames.filepaths_array, "mode1");
                    }
                    else if (mode == "mode2")
                    {
                        Result_Window res_wind = new Result_Window(search_dir.directory_names_array, search_dir.directory_paths_array, "mode2");
                    }
                
                    else if (mode == "mode3")
                    {
                        Result_Window res_wind = new Result_Window(search_files.file_arr, search_files.filepaths_array, search_files.offset_arr, search_files.text_preview, "mode3");
                    }
                
                }
            }
        });
    
    
                pause_b.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    if (pause_b.getText() == "Pause")
                    {
                        timer.stop();
                        timer2.stop();
                        
                        if (mode == "mode1")
                            search_filenames.suspend();
                        else if (mode == "mode2")
                            search_dir.suspend();
                        else if (mode == "mode3")
                            search_files.suspend();
                        
                        status_lab.setText("Status:  <font color=\"red\">Paused</font> ");
                        pause_b.setText("Start");
                    }
                    else
                    {
                        timer.start();
                        timer2.start();
                        
                        if (mode == "mode1")
                            search_filenames.resume();
                        else if (mode == "mode2")
                            search_dir.resume();
                        else if (mode == "mode3")
                            search_files.resume();
                        
                        status_lab.setText("Status:  <font color=\"orange\">Running</font> ");
                        pause_b.setText("Pause");
                    }
                }
            });    
            
        
    }
    

    

private String seconds_to_time(int seconds)
{
  TimeZone tz = TimeZone.getTimeZone("UTC");
  SimpleDateFormat df = new SimpleDateFormat("HH:mm:ss");
  df.setTimeZone(tz);
  String time = df.format(new Date(seconds*1000L));

  return time;
}


    
    

}
