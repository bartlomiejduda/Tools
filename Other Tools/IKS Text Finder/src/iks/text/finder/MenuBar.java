package iks.text.finder;


import java.awt.ComponentOrientation;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import javax.swing.Box;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

public class MenuBar 
{
    public JMenuBar Create_new_menu_bar()
    {
        JMenuBar menu_bar = new JMenuBar();
        JMenu file = new JMenu("File");
        file.setMnemonic(KeyEvent.VK_F);
        JMenuItem exit = new JMenuItem("Exit");
        exit.setMnemonic(KeyEvent.VK_E);
        exit.setToolTipText("Exit application");
        exit.addActionListener((ActionEvent event) -> 
        {
            System.exit(0);
        });
        file.add(exit);
        
        
        JMenu addons = new JMenu("Addons");
        addons.setMnemonic(KeyEvent.VK_A);
        JMenuItem update = new JMenuItem("Update registry entry");
        update.setMnemonic(KeyEvent.VK_U);
        
        update.addActionListener((ActionEvent event) -> 
        {
            Update_Registry upd_reg = new Update_Registry();
        });
        addons.add(update);
        
        
        
        JMenu help = new JMenu("Help");
        help.setMnemonic(KeyEvent.VK_H); 
        
        JMenuItem donations = new JMenuItem("Donations");
        donations.setMnemonic(KeyEvent.VK_A);
        donations.setToolTipText("About this tool");
        donations.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
        donations.addActionListener((ActionEvent event_0) -> 
        {

            JOptionPane.showMessageDialog(null, new MessageWithLink(
                    "If you want to support me,<br>" 
                    + "you can do it here:<br><br>"
                    +  "<a href=\"https://www.paypal.me/kolatek55\">https://www.paypal.me/kolatek55</a>"), "Donations", 1);
            
        });   
         help.add(donations);
        
        
        JMenuItem about = new JMenuItem("About");
        about.setMnemonic(KeyEvent.VK_A);
        about.setToolTipText("About this tool");
        about.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
        about.addActionListener((ActionEvent event) -> 
        {
    
            JOptionPane.showMessageDialog(null, new MessageWithLink(
                    "Program created by Ikskoks for Xentax community.<br><br>" 
                    + "If you like my tool, please consider visiting my site and my fanpage:<br><br>"
                    +  "<a href=\"https://www.facebook.com/ikskoks/\">https://www.facebook.com/ikskoks/</a>"
                            + "<br><a href=\"http://ikskoks.pl/\">http://ikskoks.pl/</a>"
                            ), "About", 1);
            
            
            
            
        });
        help.add(about);
        

        


        
        menu_bar.add(file);
        menu_bar.add(addons);
        menu_bar.add(Box.createGlue());
        menu_bar.add(help);
        
        return menu_bar;
    }
}
