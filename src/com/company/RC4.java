/**
     * RC4 cipher.
     *
     * Adapted from BouncyCastle.org
     * LMMB, Febrero 2017
     * 
*/
package com.company;


import java.io.*;



public class RC4
{
    private final static int STATE_LENGTH = 256;

    /*
     * variables to hold the state of the RC4 engine
     * during encryption and decryption
     */

    private byte[]      engineState = null;
    private int         x = 0;
    private int         y = 0;
    private byte[]      workingKey = null;

    /**
     * initialize a RC4 cipher. 
     * @param key key for the cipher.
     */
    public void init(byte[] key){
            workingKey = key;
            setKey(workingKey);
    }


    public String getAlgorithmName()
    {
        return "RC4";
    }

    public byte returnByte(byte in)
    {
        x = (x + 1) & 0xff;
        y = (engineState[x] + y) & 0xff;

        // swap
        byte tmp = engineState[x];
        engineState[x] = engineState[y];
        engineState[y] = tmp;

        // xor
        return (byte)(in ^ engineState[(engineState[x] + engineState[y]) & 0xff]);
    }

    public void processBytes(
        byte[]     in, 
        int     inOff, 
        int     len, 
        byte[]     out, 
        int     outOff)
    {
        if ((inOff + len) > in.length)
        {
            System.out.println("input buffer too short");
        }

        if ((outOff + len) > out.length)
        {
        	System.out.println("output buffer too short");
        }

        for (int i = 0; i < len ; i++)
        {
            x = (x + 1) & 0xff;
            y = (engineState[x] + y) & 0xff;

            // swap
            byte tmp = engineState[x];
            engineState[x] = engineState[y];
            engineState[y] = tmp;

            // xor
            out[i+outOff] = (byte)(in[i + inOff]
                    ^ engineState[(engineState[x] + engineState[y]) & 0xff]);
        }
    }

    public void reset()
    {
        setKey(workingKey);
    }

    // Private implementation

    private void setKey(byte[] keyBytes)
    {
        workingKey = keyBytes;

        // System.out.println("the key length is ; "+ workingKey.length);

        x = 0;
        y = 0;

        if (engineState == null)
        {
            engineState = new byte[STATE_LENGTH];
        }

        // reset the state of the engine
        for (int i=0; i < STATE_LENGTH; i++)
        {
            engineState[i] = (byte)i;
        }
        
        int i1 = 0;
        int i2 = 0;

        for (int i=0; i < STATE_LENGTH; i++)
        {
            i2 = ((keyBytes[i1] & 0xff) + engineState[i] + i2) & 0xff;
            // do the byte-swap inline
            byte tmp = engineState[i];
            engineState[i] = engineState[i2];
            engineState[i2] = tmp;
            i1 = (i1+1) % keyBytes.length; 
        }
    }


  public static void main(String args[]) throws Exception {
	
      String keyword = "Key";
      String texto= "Plaintext";
            
	  System.out.println("\nBiometr�a y Seguridad de Sistemas");
	  System.out.println("Ejemplo de RC4 v0.1 febrero 2017, LMMB\n");
	  System.out.print("Introduce la clave (hasta 256 caracteres):");
	  BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	  keyword = br.readLine();
	  
	  System.out.print("\nIntroduce el texto a cifrar:");
	  texto = br.readLine();
	  
      byte[] keytest = keyword.getBytes(); //convert keyword to byte

      
      byte[] text = texto.getBytes();
      
      byte[] cipher = new byte[text.length];
      byte[] backtext = new byte[text.length];
            
      System.out.print("\nplain text:    ");
      for (int i = 0; i < text.length; i++) {          
          System.out.printf("0x%02X",text[i]);          
      }    

      //encryption
      RC4 rc4 = new RC4();
      rc4.init(keytest);
      rc4.processBytes(text,0,text.length,cipher,0);

      System.out.print("\ncipher text:   ");
      for (int i = 0; i < cipher.length; i++) {          
          System.out.printf("0x%02X",cipher[i]);          
      }    

      
      //decryption
      rc4 = new RC4();
      rc4.init(keytest);
      rc4.processBytes(cipher,0,cipher.length,backtext,0);
      
      System.out.print("\ndecipher text: ");
      for (int i = 0; i < backtext.length; i++) {          
          System.out.printf("0x%02X",backtext[i]);            
      } 
      System.out.println();
  }  
}

