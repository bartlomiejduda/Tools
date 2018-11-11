package iks.text.finder;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.text.ParseException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFormattedTextField;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.text.MaskFormatter;
import net.miginfocom.swing.MigLayout;

public class Insert_Hex_Window extends JFrame
{
    Insert_Hex_Window()
    {
        this.setSize(220, 150);
        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        this.setTitle("Insert hex");
        this.setResizable(false);
        this.setLocationRelativeTo(null);
                    
         
        
        JPanel panel = new JPanel(new MigLayout("gap 0 0, , hidemode 2"));
         
         JLabel lab1 = new JLabel("Hex: ");
         panel.add(lab1, "pos 60 20, h 20, w 50");

        
        MaskFormatter formatter = null;
        try {
            formatter = new MaskFormatter("HH");
        } catch (ParseException ex) { ex.printStackTrace(); }
        JFormattedTextField hex_text = new JFormattedTextField(formatter);
         panel.add(hex_text, "pos 95 20, h 20, w 50");
         hex_text.setText("");
         JButton insert_b = new JButton("Insert");
         panel.add(insert_b, "pos 20 55, h 20, w 50");
         
         JButton cancel_b = new JButton("Cancel");
         panel.add(cancel_b, "pos 100 55, h 20, w 50");
         
         
         
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
                    String text = hex_text.getText();
                    if (!text.contains(" ") || text != "")
                    {
                    text = "{" + text + "}";
                    String old_text = IKSTextFinder.text_to_search.getText();
                    IKSTextFinder.text_to_search.setText(old_text + text);
                    IKSTextFinder.lab2.setText("Preview: " + Preview_parse.Parse(old_text) + Preview_parse.Parse(text));
                    }
                }
            });
         
         
        
        this.add(panel);
        this.setVisible(true);
    }
}
