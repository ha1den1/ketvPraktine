package org.example;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class Main extends JFrame {
    private JTextField textField1, textField2, textField3;
    private JButton signButton, verifyButton;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public Main() {
        super("RSA Digital Signature Application");

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(400, 200);
        setLayout(new GridLayout(4, 2));

        JLabel label1 = new JLabel("Įveskite tekstą:");
        textField1 = new JTextField();
        JLabel label2 = new JLabel("Skaitmeninis parašas:");
        textField2 = new JTextField();
        signButton = new JButton("Parašyti");
        JLabel label3 = new JLabel("Palyginimo rezultatas:");
        textField3 = new JTextField();
        verifyButton = new JButton("Tikrinti");

        add(label1);
        add(textField1);
        add(label2);
        add(textField2);
        add(signButton);
        add(label3);
        add(textField3);
        add(verifyButton);

        signButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sign();
            }
        });

        verifyButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                verify();
            }
        });

        generateKeyPair();

        setVisible(true);
    }

    private void generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String generateSignature(String text) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(text.getBytes());
            byte[] signatureBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private boolean verifySignature(String text, String signature) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(text.getBytes());
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            return sig.verify(signatureBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private void sign() {
        String text = textField1.getText();
        String signature = generateSignature(text);
        textField2.setText(signature);
    }

    private void verify() {
        String text = textField1.getText();
        String signature = textField2.getText();
        String comparisonText = textField3.getText();

        boolean result = verifySignature(text, signature);

        if (result && signature.equals(comparisonText)) {
            textField3.setText("Parašas patvirtintas");
        } else {
            textField3.setText("Parašas nepatvirtintas");
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new Main();
            }
        });
    }
}
