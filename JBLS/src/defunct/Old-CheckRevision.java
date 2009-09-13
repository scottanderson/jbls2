/*
 * CheckRevision.java
 *
 * Created on March 10, 2004, 9:05 AM
 */
package defunct;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.util.Hashtable;
import java.util.StringTokenizer;

import util.Out;

/** This takes care of the CheckRevision() for the main game files of any program.
 * This is done to prevent tampering and to make sure the version is correct.
 * <P>
 * This function is generally slow because it has to read through the entire
 * files.  The majority of the time is spent in i/o, but I've tried to optimize
 * this as much as possible.
 * @author iago
 */
class OldCheckRevision
{
    /** These are the hashcodes for the various .mpq files. */
    private static final int hashcodes[] = { 0xE7F4CB62, 0xF6A14FFC, 0xAA5504AF, 0x871FCDC2, 0x11BF6A18, 0xC57292E6, 0x7927D27E, 0x2FEC8733 };

    /** Stores some past results */
    private static Hashtable<String, Integer> crCache = new Hashtable<String, Integer>();
    private static int crCacheHits = 0;
    private static int crCacheMisses = 0;

    /** Does the actual version check.
     * @param versionString The version string.  This is recieved from Battle.net in 0x50 (SID_AUTH_INFO) and
     * looks something like "A=5 B=10 C=15 4 A=A+S B=B-A A=S+B C=C-B".
     * @param files The array of files we're checking.  Generally the main game files, like
     * Starcraft.exe, Storm.dll, and Battle.snp.
     * @param mpqNum The number of the mpq file, from 0..7.
     * @throws FileNotFoundException If the datafiles aren't found.
     * @throws IOException If there is an error reading from one of the datafiles.
     * @return The 32-bit CheckRevision hash.
     */
    public static int checkRevision(String versionString, String[] files, int mpqNum) throws FileNotFoundException, IOException
    {
        Integer cacheHit = (Integer) crCache.get(versionString + mpqNum + files[0]);
        if(cacheHit != null)
        {
            crCacheHits++;
            Out.println("CREV", "CheckRevision cache hit: " + crCacheHits + " hits, " + crCacheMisses + " misses.");
            return cacheHit.intValue();
        }

        crCacheMisses++;
        Out.println("CREV", "CheckRevision cache miss: " + crCacheHits + " hits, " + crCacheMisses + " misses.");

        // Break this apart at the spaces
        StringTokenizer tok = new StringTokenizer(versionString, " ");

        // Get the values for a, b, and c
        int a = Integer.parseInt(tok.nextToken().substring(2));
        int b = Integer.parseInt(tok.nextToken().substring(2));
        int c = Integer.parseInt(tok.nextToken().substring(2));

        tok.nextToken();

        String formula;

        formula = tok.nextToken();
        if(formula.matches("A=A.S") == false)
            return checkRevisionSlow(versionString, files, mpqNum);
        char op1 = formula.charAt(3);

        formula = tok.nextToken();
        if(formula.matches("B=B.C") == false)
            return checkRevisionSlow(versionString, files, mpqNum);
        char op2 = formula.charAt(3);

        formula = tok.nextToken();
        if(formula.matches("C=C.A") == false)
            return checkRevisionSlow(versionString, files, mpqNum);
        char op3 = formula.charAt(3);

        formula = tok.nextToken();
        if(formula.matches("A=A.B") == false)
            return checkRevisionSlow(versionString, files, mpqNum);
        char op4 = formula.charAt(3);


        // Now we actually do the hashing for each file
        // Start by hashing A by the hashcode
        a ^= hashcodes[mpqNum];

        for(int i = 0; i < files.length; i++)
        {
            File currentFile = new File(files[i]);
            int roundedSize = (int)((currentFile.length() / 1024) * 1024);

            MappedByteBuffer fileData = new FileInputStream(currentFile).getChannel().map(FileChannel.MapMode.READ_ONLY, 0, roundedSize);
            fileData.order(ByteOrder.LITTLE_ENDIAN);

            for(int j = 0; j < roundedSize; j += 4)
            {
                int s = fileData.getInt(j);

                // A=1054538081 B=741521288 C=797042342 4 A=A^S B=B-C C=C^A A=A+B

                switch(op1)
                {
                    case '^':
                        a = a ^ s;
                        break;
                    case '-':
                        a = a - s;
                        break;
                    case '+':
                        a = a + s;
                        break;
                }

                switch(op2)
                {
                    case '^':
                        b = b ^ c;
                        break;
                    case '-':
                        b = b - c;
                        break;
                    case '+':
                        b = b + c;
                        break;
                }

                switch(op3)
                {
                    case '^':
                        c = c ^ a;
                        break;
                    case '-':
                        c = c - a;
                        break;
                    case '+':
                        c = c + a;
                        break;
                }

                switch(op4)
                {
                    case '^':
                        a = a ^ b;
                        break;
                    case '-':
                        a = a - b;
                        break;
                    case '+':
                        a = a + b;
                        break;
                }
            }
        }
        System.gc();

        crCache.put(versionString + mpqNum + files[0], new Integer(c));
        return c;
    }


    /** This is an alternate implementation of CheckRevision.  It it slower (about 2.2 times slower), but it can handle
     * weird version strings that Battle.net would never send.  Battle.net's version strings are _always_ in the form:
     * A=x B=y C=z 4 A=A?S B=B?C C=C?A A=A?B:
     *
     * A=1054538081 B=741521288 C=797042342 4 A=A^S B=B-C C=C^A A=A+B
     *
     * If, for some reason, the string in checkRevision() doesn't match up, this will run.
     *
     * @param versionString The version string.  This is recieved from Battle.net in 0x50 (SID_AUTH_INFO) and
     * looks something like "A=5 B=10 C=15 4 A=A+S B=B-A A=S+B C=C-B".
     * @param files The array of files we're checking.  Generally the main game files, like
     * Starcraft.exe, Storm.dll, and Battle.snp.
     * @param mpqNum The number of the mpq file, from 1..7.
     * @throws FileNotFoundException If the datafiles aren't found.
     * @throws IOException If there is an error reading from one of the datafiles.
     * @return The 32-bit CheckRevision hash.
     */
    private static int checkRevisionSlow(String versionString, String[] files, int mpqNum) throws FileNotFoundException, IOException
    {
        System.out.println("Warning: using checkRevisionSlow for version string: " + versionString);
        Integer cacheHit = (Integer) crCache.get(versionString + mpqNum + files[0]);
        if(cacheHit != null)
        {
            crCacheHits++;
            System.out.println("CheckRevision cache hit");
            System.out.println(" --> " + crCacheHits + " hits, " + crCacheMisses + " misses.");
            return cacheHit.intValue();
        }

        crCacheMisses++;
        System.out.println("CheckRevision cache miss");
        System.out.println("--> " + crCacheHits + " hits, " + crCacheMisses + " misses.");


        // First, parse the versionString to name=value pairs and put them
        // in the appropriate place
        int[] values = new int[4];

        int[] opValueDest = new int[4];
        int[] opValueSrc1 = new int[4];
        char[] operation = new char[4];
        int[] opValueSrc2 = new int[4];

        // Break this apart at the spaces
        StringTokenizer s = new StringTokenizer(versionString, " ");
        int currentFormula = 0;
        while(s.hasMoreTokens())
        {
            String thisToken = s.nextToken();
            // As long as there is an '=' in the string
            if(thisToken.indexOf('=') > 0)
            {
                // Break it apart at the '='
                StringTokenizer nameValue = new StringTokenizer(thisToken, "=");
                if(nameValue.countTokens() != 2)
                    return 0;

                int variable = getNum(nameValue.nextToken().charAt(0));

                String value = nameValue.nextToken();

                // If it starts with a number, assign that number to the appropriate variable
                if(Character.isDigit(value.charAt(0)))
                {
                    values[variable] = Integer.parseInt(value);
                }
                else
                {
                    opValueDest[currentFormula] = variable;

                    opValueSrc1[currentFormula] = getNum(value.charAt(0));
                    operation[currentFormula] = value.charAt(1);
                    opValueSrc2[currentFormula] = getNum(value.charAt(2));

                    currentFormula++;
                }
            }
        }

        // Now we actually do the hashing for each file
        // Start by hashing A by the hashcode
        values[0] ^= hashcodes[mpqNum];

        for(int i = 0; i < files.length; i++)
        {
            File currentFile = new File(files[i]);
            int roundedSize = (int)((currentFile.length() / 1024) * 1024);

            MappedByteBuffer fileData = new FileInputStream(currentFile).getChannel().map(FileChannel.MapMode.READ_ONLY, 0, roundedSize);
            fileData.order(ByteOrder.LITTLE_ENDIAN);

            for(int j = 0; j < roundedSize; j += 4)
            {
                values[3] = fileData.getInt(j);

                for(int k = 0; k < currentFormula; k++)
                {
                    switch(operation[k])
                    {
                        case '+':
                            values[opValueDest[k]] = values[opValueSrc1[k]] + values[opValueSrc2[k]];
                            break;

                        case '-':
                            values[opValueDest[k]] = values[opValueSrc1[k]] - values[opValueSrc2[k]];
                            break;

                        case '^':
                            values[opValueDest[k]] = values[opValueSrc1[k]] ^ values[opValueSrc2[k]];
                    }
                }
             }
        }

        crCache.put(versionString + mpqNum + files[0], new Integer(values[2]));

        return values[2];
    }

    /** Converts the parameter to which number in the array it is, based on A=0, B=1, C=2, S=3.
     * @param c The character letter.
     * @return The array number this is found at.
     */
    private static int getNum(char c)
    {
        c = Character.toUpperCase(c);
        if(c == 'S')
            return 3;

        return c - 'A';
    }

    	public static String hex(int val){
		return Integer.toString((val & 0xF0000000) >>> 28, 16) +
			   Integer.toString((val & 0x0F000000) >> 24,  16) +
			   Integer.toString((val & 0x00F00000) >> 20,  16) +
			   Integer.toString((val & 0x000F0000) >> 16,  16) +
			   Integer.toString((val & 0x0000F000) >> 12,  16) +
			   Integer.toString((val & 0x00000F00) >> 8,   16) +
			   Integer.toString((val & 0x000000F0) >> 4,   16) +
			   Integer.toString((val & 0x0000000F) >> 0,   16);
	}
}
