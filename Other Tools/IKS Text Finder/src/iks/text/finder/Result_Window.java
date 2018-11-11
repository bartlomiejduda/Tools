
package iks.text.finder;

import java.awt.Desktop;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.text.SimpleDateFormat;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import net.miginfocom.swing.MigLayout;

public class Result_Window extends JFrame
{
    public List<String> filenames;
    public List<String> file_paths;
    public String mode;
    
    public List<String> offsets;
    public List<String> text_previews;
    
    //modes 1-2 and 4-5
    Result_Window(List<String> filenames, List<String> file_paths, String mode)
    {
        this.filenames = filenames;
        this.file_paths = file_paths;
        this.mode = mode;
        run_window();
    }
    
    //mode 3
    Result_Window(List<String> filenames, List<String> file_paths, List<String> offsets, List<String> text_previews, String mode)
    {
        this.filenames = filenames;
        this.file_paths = file_paths;
        this.offsets = offsets;
        this.text_previews = text_previews;
        this.mode = mode;
        run_window();
    }
    

    
    
    public void run_window()
    {
        this.setSize(720, 450);
        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        this.setTitle("Results");
        //this.setResizable(false);
        this.setLocationRelativeTo(null);
                    
         JPanel panel = new JPanel(new MigLayout("gap 0 0, , hidemode 2"));
         
         
         
         
        JTable tt = new JTable();
        DefaultTableModel model = new DefaultTableModel();
        //panel.add(tt, "pos 89% 5%, h 20, w 80%, grow") ;
        JScrollPane scrollPane = new JScrollPane(tt, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
       panel.add(scrollPane, "pos 20 5%, h 60%, w 100% - 40px");
       
       
       if (mode == "mode3")
       {
           model.addColumn("File");
            model.addColumn("Result");
            model.addColumn("Offset (DEC)");
            model.addColumn("Offset (HEX)");
        
            int item_count = 0;

            for (String text_prev : text_previews) 
            {
                String hex_offset = Integer.toHexString(Integer.parseInt(offsets.get(item_count)));
                model.addRow((new Object[]{filenames.get(item_count), text_prev, offsets.get(item_count), hex_offset}));
                item_count +=1;
            }
           
           
           
       }
       else
       {
           if (mode == "mode1")
           {
               model.addColumn("Filename");
               model.addColumn("Filepath");
           }
            
           else
           {
               model.addColumn("Directory name");
               model.addColumn("Directory path");
           }


            int i = 0;
            for (String filename : filenames)
            {
                model.addRow((new Object[]{filename, file_paths.get(i)}));
                i++;
            }
       
       }
       
       tt.setModel(model);
        
        JButton prop_b = new JButton();
        panel.add(prop_b, "pos 41.8% 70%, h 30, w 70");
        prop_b.setText("Properties");
       
       
       JButton open_file_b = new JButton();
        panel.add(open_file_b, "pos 25% 70%, h 30, w 70");
        open_file_b.setText("Open File");
        
        JButton open_folder_b = new JButton();
        panel.add(open_folder_b, "pos 60% 70%, h 30, w 70");
        open_folder_b.setText("Open Folder");
        
       
        
        
        prop_b.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                  if (!tt.getSelectionModel().isSelectionEmpty())
                  {
                    Result_Properties_Window prop_window = new Result_Properties_Window();
                    int column;
                    int row = tt.getSelectedRow();
                    
                    if (mode == "mode1" || mode == "mode3")
                    {
                        String filepath_p;
                        if (mode == "mode1")
                        {
                            column = 0;
                            String filename_p = tt.getModel().getValueAt(row, column).toString();
                            prop_window.add_property("Filename: " + filename_p);
                            column = 1;
                            filepath_p = tt.getModel().getValueAt(row, column).toString();
                            prop_window.add_property("Filepath: " + filepath_p);
                            prop_window.add_property("");
                        }
                        else
                        {
                            column = 0;
                            filepath_p = tt.getModel().getValueAt(row, column).toString();
                            prop_window.add_property("Filepath: " + filepath_p);
                            prop_window.add_property("");
                            
                            Path temp_p = Paths.get(filepath_p);
                            
                            prop_window.add_property("Filename: " + temp_p.getFileName().toString());
                        }
                        
                        Path path = Paths.get(filepath_p);
                        try {
                            BasicFileAttributes attr = Files.readAttributes(path, BasicFileAttributes.class);
                            
                            prop_window.add_property("Is regular file: " + bool_to_str(attr.isRegularFile()));
                            prop_window.add_property("Is directory: " + bool_to_str(attr.isDirectory()));
                            prop_window.add_property("Is other: " + bool_to_str(attr.isOther()));
                            prop_window.add_property("Is symbolic link: " + bool_to_str(attr.isSymbolicLink()));
                            prop_window.add_property("");
                            
                            SimpleDateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
                            
                            prop_window.add_property("Creation time: " + df.format(attr.creationTime().toMillis()));
                            prop_window.add_property("Last access time: " + df.format(attr.lastAccessTime().toMillis()));
                            prop_window.add_property("Last modified time: " + df.format(attr.lastModifiedTime().toMillis()));
                            prop_window.add_property("File size: " + attr.size() + " bytes");
                            prop_window.add_property("File size (kb): " + bytes_to_kb(attr.size()));
                            prop_window.add_property("File size (mb): " + bytes_to_mb(attr.size()));
                            prop_window.add_property("File size (gb): " + bytes_to_gb(attr.size()));
                            
                            
                            
                        } catch (IOException ex) { ex.printStackTrace();}
                    }
                    
                    else if (mode == "mode2")
                    {
                        column = 0;
                        String directory_p = tt.getModel().getValueAt(row, column).toString();
                        prop_window.add_property("Directory name: " + directory_p);
                        
                        
                        column = 1;
                        String dirpath_p = tt.getModel().getValueAt(row, column).toString();
                        prop_window.add_property("Directory path: " + dirpath_p + "\\");
                        prop_window.add_property("");
                        
                        
                        Path path = Paths.get(dirpath_p);
                        try {
                            BasicFileAttributes attr = Files.readAttributes(path, BasicFileAttributes.class);
                            
                            prop_window.add_property("Is regular file: " + bool_to_str(attr.isRegularFile()));
                            prop_window.add_property("Is directory: " + bool_to_str(attr.isDirectory()));
                            prop_window.add_property("Is other: " + bool_to_str(attr.isOther()));
                            prop_window.add_property("Is symbolic link: " + bool_to_str(attr.isSymbolicLink()));
                            prop_window.add_property("");
                            
                            SimpleDateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
                            
                            prop_window.add_property("Creation time: " + df.format(attr.creationTime().toMillis()));
                            prop_window.add_property("Last access time: " + df.format(attr.lastAccessTime().toMillis()));
                            prop_window.add_property("Last modified time: " + df.format(attr.lastModifiedTime().toMillis()));
                            
                            
                            
                        } catch (IOException ex) { ex.printStackTrace();}
                        
                        
                    }

                    prop_window.set_visible();
                    
                  }
                }
            });
        
        if (mode == "mode2")
         {
             open_file_b.setEnabled(false);
         }
        
        open_file_b.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                  if (!tt.getSelectionModel().isSelectionEmpty())
                  {
                    int column = 1;
                    if (mode == "mode3")
                        column = 0;
                    
                    int row = tt.getSelectedRow();
                    String path = tt.getModel().getValueAt(row, column).toString();
                    //System.out.println(path);
                    File dir = new File(path);
                    
                    try {
                        Desktop.getDesktop().edit(dir);

                    } catch (IOException ex) {
                        
                        
                        try { Desktop.getDesktop().open(dir); }
                        catch (Exception exx) {
                         JOptionPane.showMessageDialog(null, "You can't preview this file!", "InfoBox", JOptionPane.INFORMATION_MESSAGE);
                        //ex.printStackTrace();
                        
                        }
                        
                        
                        
                    }
                    
                  }

                }
            });
        
        
        open_folder_b.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                  if (!tt.getSelectionModel().isSelectionEmpty())
                  {   
                    int column = 1;
                    if (mode == "mode3")
                        column = 0;
                    
                    int row = tt.getSelectedRow();
                    String path = tt.getModel().getValueAt(row, column).toString();
                    //System.out.println(path);
                    File dir = new File(path);
                    String path2 = dir.getPath();
                    
                    if (mode != "mode2")
                        path2 = dir.getParent();
                    
                    try {
                        Desktop.getDesktop().open(new File(path2));
                    } catch (IOException ex) {
                        JOptionPane.showMessageDialog(null, "You can't open this folder!", "InfoBox", JOptionPane.INFORMATION_MESSAGE);
                       
                        //ex.printStackTrace();
                    } 

                  }
                }
            });
        
        
        this.add(panel);
        this.setVisible(true);
    }
    
    
    
    public String bool_to_str(boolean bool)
    {
        if (bool == true)
            return "YES";
        else
            return "NO";
    }
    
    
    public String bytes_to_kb(long bytes)
    {
        double kb = (double)bytes / 1024.0;
        String s = String.format("%.2f", kb);
        return s;
    }
    
    public String bytes_to_mb(long bytes)
    {
        double mb = (double)bytes / 1024.0 / 1024.0;
        String s = String.format("%.2f", mb);
        return s;
    }
    
    public String bytes_to_gb(long bytes)
    {
        double gb = (double)bytes / 1024.0 / 1024.0 / 1024.0;
        String s = String.format("%.2f", gb);
        return s;
    }
    
}
