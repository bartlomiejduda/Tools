package iks.text.finder;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import net.miginfocom.swing.MigLayout;

public class Insert_Special_Window extends JFrame
{
    Insert_Special_Window()
    {
        this.setSize(420, 170);
        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        this.setTitle("Insert Special");
        this.setResizable(false);
        this.setLocationRelativeTo(null);
                    
         
        
        JPanel panel = new JPanel(new MigLayout("gap 0 0, , hidemode 2"));
         
         JLabel lab1 = new JLabel("Text: ");
         panel.add(lab1, "pos 20 20, h 20, w 50");


        JTextField special_text = new JTextField();
         panel.add(special_text, "pos 55 20, h 20, w 300");
         special_text.setText("");
         
         
         JLabel lab2 = new JLabel("Insert as: ");
         panel.add(lab2, "pos 20 50, h 20, w 50");
         
         
         JComboBox comb = new JComboBox();
         comb.addItem("US-ASCII");
         comb.addItem("ISO-8859-1");
         comb.addItem("UTF-8");
         comb.addItem("UTF-16BE");
         comb.addItem("UTF-16LE");
         comb.addItem("UTF-16");
         panel.add(comb, "pos 85 50, h 20, w 200");
         
         
         
         JButton insert_b = new JButton("Insert");
         panel.add(insert_b, "pos 120 85, h 20, w 50");
         
         JButton cancel_b = new JButton("Cancel");
         panel.add(cancel_b, "pos 200 85, h 20, w 50");
         
         
         
         cancel_b.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    dispose();
                }
            });
         
         
         insert_b.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    String ins_mode = comb.getSelectedItem().toString();
                    String text = special_text.getText();
                    
                    
                        try {
                            byte[] b = text.getBytes(ins_mode);
                            text = Binary_parse.byte_array_to_string(b);
                        } catch (UnsupportedEncodingException ex) {ex.printStackTrace();} 
                    
                            
                  
   
                    String old_text = IKSTextFinder.text_to_search.getText();
                    IKSTextFinder.text_to_search.setText(old_text + text);
                    IKSTextFinder.lab2.setText("Preview: " + Preview_parse.Parse(old_text) + Preview_parse.Parse(text));
   
                        
                }

            });
  
        this.add(panel);
        this.setVisible(true);
    }
}
