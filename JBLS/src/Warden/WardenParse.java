package Warden;

import util.Buffer;
import util.PadString;
import Warden.SimpleCrypto;
import Warden.WardenModule;
import Warden.WardenRandom;

public class WardenParse extends Thread {
	
	  private byte[] 	   keyhash = null;
	  private SimpleCrypto incoming = null;
	  private SimpleCrypto outgoing = null;
	  private WardenModule warden_module = null;
	  private Buffer	   buffer_return = new Buffer();
	  
  public Buffer ParseWarden(Buffer in)
  {
      if(incoming == null || outgoing == null)
      {
        System.out.println("Generating Cryptos");
        WardenRandom rand = new WardenRandom(this.keyhash);
        this.outgoing = new SimpleCrypto(rand.getBytes(0x10));
        this.incoming = new SimpleCrypto(rand.getBytes(0x10));
      }
      
      in.removeDWord(); //header
      Buffer warden = new Buffer();
      warden.addBytes(incoming.do_crypt(in.getBuffer()));
      //System.out.println(warden.toString());
      int opcode = warden.removeByte();
      switch(opcode)
      {
        case 0x00: //Startup
            
          byte[] md5        = warden.removeBytes(0x10);
          byte[] decryption = warden.removeBytes(0x10);
          int length        = warden.removeDWord();
          
          warden_module = new WardenModule(length, md5, decryption);
          
          System.out.println("Received warden module info: ");
          System.out.println("  Name:           " + warden_module.getName() + ".mod");
          System.out.println("  Decryption Key: " + warden_module.getSeed());
          System.out.println("  Length:         " + warden_module.getSize());
          
          Buffer out = new Buffer();
          
          if(warden_module.alreadyExists())
          {
            System.out.println("Module already exists");
            out.addBytes(outgoing.do_crypt((byte)1));
          } else {
            System.out.println("Downloading Module");
            out.addBytes(outgoing.do_crypt((byte)0));
          }
          
          buffer_return = out;
          break;
          
        case 0x01:
          length = warden.removeWord();
          System.out.println("Received warden part length: " + length);
          byte[] data = warden.removeBytes(length);
          warden_module.savePart(data, length);
          
          if(warden_module.downloadComplete())
          {
            out = new Buffer(); 
            if(warden_module.alreadyExists()){
              System.out.println("Download successfull");
              out.addBytes(outgoing.do_crypt((byte)1));
              //warden_module.setup();
            } else {
              System.out.println("Downloading failed");
              out.addBytes(outgoing.do_crypt((byte)0));
              warden_module.reset();
            }
            buffer_return = out;
          }
        break;
        
        case 0x02:
          Buffer modRet = warden_module.handleRequest(warden);
          
          data = modRet.removeBytes(0x20);
          int checksum = modRet.removeDWord();
          switch(checksum)
          {
            case 123: checksum = 0x193E73E8; break;
            case 132: checksum = 0x2183172A; break;
            case 213: checksum = 0xD6557DEF; break;
            case 231: checksum = 0xCA841860; break;
            case 312: checksum = 0xC04CF757; break;
            case 321: checksum = 0x9F2AD2C3; break;
          }
          /*
            0x00497FB0, 0x0049C33D, 0x004A2FF7  = 0x193E73E8
            0x00497FB0, 0x004A2FF7, 0x0049C33D  = 0x2183172A

            0x0049C33D, 0x00497FB0, 0x004A2FF7  = 0xD6557DEF
            0x0049C33D, 0x004A2FF7, 0x00497FB0  = 0xCA841860

            0x004A2FF7, 0x0049C33D, 0x00497FB0  = 0x9F2AD2C3
            0x004A2FF7, 0x00497FB0, 0x0049C33D  = 0xC04CF757
          */
          
          Buffer response = new Buffer();
          response.addByte((byte)0x02);
          response.addWord((short)data.length);
          response.addDWord(checksum);
          response.addBytes(data);
          System.out.println(response.toString());
          
          out = new Buffer(); 
          out.addBytes(outgoing.do_crypt(response.getBuffer()));
          
          buffer_return = out;
          break;
          
        case 0x05:
        	long rc4 = 0;
        	if (!warden_module.downloadComplete())
        	{
        		System.out.println("Warden module still downloading.");
        		break;
        	}
        	
        	
        default:
          System.out.println("Unknown Warden opcode: 0x" + PadString.padHex(opcode, 2));
          buffer_return = null;
      }
      return buffer_return;
    }
}
