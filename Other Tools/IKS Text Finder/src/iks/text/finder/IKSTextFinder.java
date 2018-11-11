
package iks.text.finder;

import java.awt.Checkbox;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import net.miginfocom.swing.MigLayout;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JEditorPane;
import javax.swing.JMenuBar;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextPane;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;


public class IKSTextFinder 
{
    public int window_height = 500;
    public int window_width = 480;
    public String window_title = "IKS Text Finder v0.7";
    public int result = -1;
    String search_dir_path = "a";
    String text = "b";
    public static JTextField text_to_search;
    public static JEditorPane lab2;
    public static String arg_path;
    JTextField search_directory;
    JComboBox comb;
    Checkbox c2;
    JTable tt;
    DefaultTableModel model;
    
    public static void main(String[] args)
    {
        if (args.length > 0)
        {
            arg_path = args[0];
        }
            
        IKSTextFinder kk = new IKSTextFinder(args);
    }
    
    
    public IKSTextFinder(String[] args) 
    {
        JFrame.setDefaultLookAndFeelDecorated(false);
            JFrame my_window = new JFrame();
            my_window.setSize(window_width, window_height);
            my_window.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            my_window.setTitle(window_title);
            my_window.setResizable(false);
            my_window.setLocationRelativeTo(null);
            
            MenuBar my_menu = new MenuBar();
            JMenuBar menu_bar = my_menu.Create_new_menu_bar();
            my_window.setJMenuBar(menu_bar);
            
            
         JPanel panel = new JPanel(new MigLayout("gap 0 0, , hidemode 2"));
         
         JLabel lab1 = new JLabel("Text: ");
         panel.add(lab1, "pos 20 20, h 20, w 50");
         
         text_to_search = new JTextField();
         text_to_search.setText("");
         Font f = text_to_search.getFont();
         panel.add(text_to_search, "pos 55 20, h 20, w 400");
         
         lab2 = new JEditorPane();
         lab2.setText("Preview: ");
         lab2.setBackground(null);
         lab2.setBorder(null);
         lab2.setEditable(false);
         panel.add(lab2, "pos 20 45, h 20, w 500");
         //lab2.setFont(f.deriveFont(f.getStyle() & ~Font.BOLD));
         
         
         JButton insert_hex_b = new JButton("Insert hex value");
         panel.add(insert_hex_b, "pos 330 70, h 20, w 30");
         
         JButton insert_special_b = new JButton("Insert special");
         panel.add(insert_special_b, "pos 330 100, h 20, w 124");

         
         insert_hex_b.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    Insert_Hex_Window ins_hex_window = new Insert_Hex_Window();
                }
            });
 
          insert_special_b.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    Insert_Special_Window ins_spec_window = new Insert_Special_Window();
                }
            });

         text_to_search.addKeyListener(new KeyAdapter()
    {
        public void keyPressed(KeyEvent ke)
        {
            if(!(ke.getKeyChar()==27||ke.getKeyChar()==65535))
            {
                
                lab2.setText("Preview: " + Preview_parse.Parse(text_to_search.getText()));
            }
        }

        public void keyReleased(KeyEvent ke) 
        {
                lab2.setText("Preview: " + Preview_parse.Parse(text_to_search.getText()));
        }
    });
         

         comb = new JComboBox();
         comb.addItem("Mode 1 - Search in filenames only");
         comb.addItem("Mode 2 - Search in directory names only");
         comb.addItem("Mode 3 - Search in binary files only ");
         //comb.addItem("Mode 4 - Relative search ");
         panel.add(comb, "pos 55 70, h 20, w 200");

         
         Checkbox c1 = new Checkbox("Show only first occurence for each file", false);
         panel.add(c1, "pos 20 130, h 20, w 200");
         c1.setVisible(false);
         c1.setEnabled(false);
         
         c2 = new Checkbox("Size of the letters matters (Match case)", false);
         panel.add(c2, "pos 20 155, h 20, w 200");
         c2.setVisible(false);
         c2.setEnabled(false);

         
         String curr_dir = System.getProperty("user.dir");
         search_directory = new JTextField();
         panel.add(search_directory, "pos 20 180, h 20, w 435");
         search_directory.setText(curr_dir + "\\");
         JButton dir_b = new JButton("Choose directory");
         panel.add(dir_b, "pos 20 200, h 20, w 30");
         JFileChooser fc = new JFileChooser();
         fc.setCurrentDirectory(new File(curr_dir + "\\"));
         fc.removeChoosableFileFilter(fc.getFileFilter());
         fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
         
         
       dir_b.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    JFrame temp = new JFrame();
                    result = fc.showOpenDialog(temp);
                    
                    if (result == JFileChooser.APPROVE_OPTION) 
                    {
                        File selectedFile = fc.getSelectedFile();
                        search_dir_path  = selectedFile.getAbsolutePath();
                        search_directory.setText(search_dir_path);
                    }

                }
            });


       
//SEARCH BUTTON
         JButton search_b = new JButton("Search");
         panel.add(search_b, "pos 20 240, h 20, w 30");
         
         search_b.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    search_dir_path = search_directory.getText();
                    text = text_to_search.getText();
                    boolean is_checked_only_five = c1.getState();
                    boolean is_checked_size_matters = c2.getState();
                    
                    int index = comb.getSelectedIndex();
                    
                    String sel_mode = comb.getSelectedItem().toString();
                    String mode;
                    
                    
                    if (sel_mode == "Mode 1 - Search in filenames only")
                    {
                        mode = "mode1";
                        text = Preview_parse.Parse(text);
                    }
                    else if (sel_mode == "Mode 2 - Search in directory names only")
                    {
                        mode = "mode2";
                        text = Preview_parse.Parse(text);
                    }
                    else if (sel_mode == "Mode 3 - Search in binary files only ")
                    {
                        mode = "mode3";
                        
                        byte[] arr = Binary_parse.Parse(text);
                        //System.out.println(new String(arr, 0));
                        Progress_Window prog_wind = new Progress_Window(mode, arr, search_dir_path, is_checked_only_five, is_checked_size_matters);
                    
                        
                    }
                    else if (sel_mode == "Mode 4 - Relative search ")
                    {
                        mode = "mode4";
                        text = Preview_parse.Parse(text);
                    }
                    else
                    {
                        mode = "mode0";
                    }
                    
                    Progress_Window prog_wind;
                    
                    if (mode != "mode3")
                        prog_wind = new Progress_Window(mode, text, search_dir_path, is_checked_only_five, is_checked_size_matters);
                    
                    
                    
                    save_to_search_history_file();
                    reload_search_table();
                    
                }
            });

         
         comb.addFocusListener(new FocusListener()
         {
             @Override
             public void focusGained(FocusEvent e) 
             {
                comb.revalidate();
                
             }

            @Override
            public void focusLost(FocusEvent e) 
            {
                comb.revalidate();
            }

         }); 
         
         
         
         comb.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    if (comb.getSelectedItem().toString() == "Mode 3 - Search in binary files only ")
                    {
                        c1.setEnabled(true);
                    }
                    else
                    {
                        c1.setEnabled(false);
                    }
                }
            });
         
         
         
         JLabel last_s_lab = new JLabel("Last searches: ");
         panel.add(last_s_lab, "pos 20 290, h 20, w 30");
         
         tt = new JTable();
         model = new DefaultTableModel();
        JScrollPane scrollPane = new JScrollPane(tt, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
       panel.add(scrollPane, "pos 20 310, h 120, w 435");
         model.addColumn("Date");
         model.addColumn("Search text");
         model.addColumn("Search directory");
         model.addColumn("Mode");
         model.addColumn("Match case");
         //model.addRow((new Object[]{"21.12.1987 19:47:23", "aa", "mode1"}));
         //model.addRow((new Object[]{"21.12.1987 19:47:23", "aa", "mode1"}));
         tt.setModel(model);
        // tt.setColumnModel((TableColumnModel) model);
         
         tt.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
         tt.getColumnModel().getColumn(0).setPreferredWidth(140); //date
         tt.getColumnModel().getColumn(1).setPreferredWidth(200); //text
         tt.getColumnModel().getColumn(2).setPreferredWidth(500); //search dir
         tt.getColumnModel().getColumn(3).setPreferredWidth(230); //mode

         
         
         
         reload_search_table();
         
         
         JButton load_b = new JButton("Load");
         panel.add(load_b, "pos 320 280, h 20, w 30");
         
         JButton clear_b = new JButton("Clear");
         panel.add(clear_b, "pos 390 280, h 20, w 30");
         
         
         load_b.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    load_search_settings();
                }
            });
         
         
         clear_b.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    clear_search_settings();
                }
            });
         
         
         
         c1.setEnabled(false);
         
         my_window.add(panel);
         comb.repaint();
         if (args.length > 0)
            search_directory.setText(arg_path + "\\");
         my_window.setVisible(true); 
    }
    
    
     public void clear_search_settings()
     {
         
         int reply = JOptionPane.showConfirmDialog(null, "Do you really want to delete your search history?", "Warning", JOptionPane.YES_NO_OPTION);
        if (reply == JOptionPane.YES_OPTION) 
        {
            
            int rowCount = model.getRowCount();
            for (int i = rowCount - 1; i >= 0; i--) 
            {
                model.removeRow(i);
            }
            
            
            String curr_path = "";
            curr_path = new File(".").getAbsolutePath();
            curr_path = curr_path.substring(0, curr_path.length()-1);

            Path hist_path= Paths.get(curr_path + "search_history.ini");
            
            
            File file = hist_path.toFile();
            
            try{
                Files.deleteIfExists(hist_path); 
            } 
            catch (Exception ex)
            {
                ex.printStackTrace();
            }

        }

         
         
         
         

     }
    
    
    
    
 public void load_search_settings()
 {
     boolean is_selected = !tt.getSelectionModel().isSelectionEmpty();
     
     if (is_selected == true)
     {
         int sel_ind = tt.getSelectedRow();
         
         String date = model.getValueAt(sel_ind, 0).toString();
         String text = model.getValueAt(sel_ind, 1).toString();
         String dir = model.getValueAt(sel_ind, 2).toString();
         String mode = model.getValueAt(sel_ind, 3).toString();
         String sel = model.getValueAt(sel_ind, 4).toString();
         
         
         String mode_c = comb.getSelectedItem().toString();
         System.out.println(mode_c);
         
         text_to_search.setText(text);
         search_directory.setText(dir);
         if ("Mode 1 - Search in filenames only".equals(mode))
             comb.setSelectedIndex(0);
            
         else if ("Mode 2 - Search in directory names only".equals(mode))
             comb.setSelectedIndex(1);
             
         else if ("Mode 3 - Search in binary files only ".equals(mode))
             comb.setSelectedIndex(2);

         else
         {
             System.out.println(("wrong mode"));
         }
             
         
         
         comb.updateUI();
         comb.repaint();
         comb.revalidate();
         
         if (sel == "true")
             c2.setState(true);
         else
             c2.setState(false);
         
         
         
     }
     
 }
    
    
    
    
    
public void save_to_search_history_file()
{
    String hist_string = "";
    
    SimpleDateFormat sdfDate = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    Date now = new Date();
    String str_date = sdfDate.format(now);
    
    
    hist_string += str_date + ";;;SEP_IKS;;;";
    hist_string += text_to_search.getText() + ";;;SEP_IKS;;;";
    hist_string += search_directory.getText() + ";;;SEP_IKS;;;";
    hist_string += comb.getSelectedItem().toString() + ";;;SEP_IKS;;;";
    
    String is_checked = "";
    if (c2.getState())
        is_checked = "true";
    else
        is_checked = "false";
    
    
    hist_string +=  is_checked + ";;;SEP_IKS;;;";
    hist_string += '\n';
    
    
    
    //////////////////////////////////////////////////////////////
    
    String curr_path = "";
    curr_path = new File(".").getAbsolutePath();
    curr_path = curr_path.substring(0, curr_path.length()-1);
    
    Path hist_path= Paths.get(curr_path + "search_history.ini");
     
    File file = new File("search_history.ini");
    if(!file.exists())
    {
        //file.getParentFile().mkdirs();
        try {
            file.createNewFile();
        } catch (IOException ex) { ex.printStackTrace(); }
        
        
        PrintWriter out = null;
        try {
            out = new PrintWriter(file);
        } catch (FileNotFoundException ex) { ex.printStackTrace(); }
        
        
       out.write(hist_string);
       out.close();
        
    }
    else
    {
        Writer output = null;
        try {
            output = new BufferedWriter(new FileWriter(file, true));
            output.append(hist_string);
            output.close();
        } catch (IOException ex) { ex.printStackTrace(); }
    }
    
    
}
    


public void reload_search_table()
{
    int rowCount = model.getRowCount();
    for (int i = rowCount - 1; i >= 0; i--) 
    {
        model.removeRow(i);
    }
    
    
        String curr_path = "";
        curr_path = new File(".").getAbsolutePath();
        curr_path = curr_path.substring(0, curr_path.length()-1);
        Path hist_path= Paths.get(curr_path + "search_history.ini");  
        File file = hist_path.toFile();
    
        if(!file.exists())
    {
        try {
            file.createNewFile();
        } catch (IOException ex) { ex.printStackTrace(); }
    }
    
    
    
    BufferedReader br = null;
    try {
        br = new BufferedReader(new FileReader("search_history.ini"));
    } catch (FileNotFoundException ex) { ex.printStackTrace(); }
    
    String line;
    String[] splitted_line;
        try 
        {
            while ((line = br.readLine()) != null)
            {
                splitted_line = line.split(";;;SEP_IKS;;;");
                model.insertRow(0, (new Object[]{splitted_line[0], splitted_line[1], splitted_line[2], splitted_line[3], splitted_line[4]}));
                
            }   
        } catch (IOException ex) { ex.printStackTrace(); }
    
        try {
            br.close();
        } catch (IOException ex) { ex.printStackTrace(); }
}



    
    
}
