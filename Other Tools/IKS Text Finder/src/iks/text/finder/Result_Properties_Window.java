
package iks.text.finder;

import java.awt.Dimension;
import javax.swing.Action;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.text.DefaultEditorKit;
import net.miginfocom.swing.MigLayout;


public class Result_Properties_Window extends JFrame
{
    JTextArea Properties_Area= new JTextArea();
    
    Result_Properties_Window()
    {
        this.setSize(720, 450);
        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        this.setTitle("Properties");
        //this.setResizable(false);
        this.setLocationRelativeTo(null);
        //this.setMinimumSize(new Dimension(30, 30));
                    
         JPanel panel = new JPanel(new MigLayout("gap 0 0, , hidemode 2"));
         
        
        Properties_Area.setLineWrap(true);
        Properties_Area.setWrapStyleWord(true);
        Properties_Area.setEditable(false);
        Properties_Area.setBackground(null); 
        Properties_Area.setBorder(null); 
        //panel.add(Properties_Area, "pos 20 20, h 100% - 40, w 100% - 40, grow, wmin 10");
        JPopupMenu menu = new JPopupMenu();
        Action copy = new DefaultEditorKit.CopyAction();
        copy.putValue(Action.NAME, "Copy");
        copy.putValue(Action.ACCELERATOR_KEY, KeyStroke.getKeyStroke("control C"));
        menu.add( copy );
        Properties_Area.setComponentPopupMenu( menu );
        
        
        JScrollPane scrollPane = new JScrollPane(Properties_Area, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
       panel.add(scrollPane, "pos 20 20, h 100% - 40, w 100% - 40, grow, wmin 10");
        
        
        panel.setOpaque(true);
         
         this.add(panel);
    }
    
    public void add_property(String new_text)
    {
        String old_text = Properties_Area.getText();
        Properties_Area.setText(old_text + '\n' + new_text);
    }
    
    public void set_visible()
    {
        this.setVisible(true);
    }
}
