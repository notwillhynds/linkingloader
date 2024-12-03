import java.io.*;
import java.util.*;

public class siclink {
    public static final int MEM_SIZE = 32768;
    public static byte[] MEM = new byte[MEM_SIZE];
    public static boolean[] MEM_USED = new boolean[MEM_SIZE];
    public static Map<String, Integer> ESTAB = new LinkedHashMap<>();
    private static List<ObjectProgram> objectPrograms = new ArrayList<>();
    private static int PROGADDR;
    public static int EXECADDR;

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java siclink filename1 filename2 ...");
            System.exit(1);
        }

        try {
            // Pass 1: Build ESTAB
            pass1(args);

            // Pass 2: Generate Object Code
            pass2();

            // Write output to outfile
            writeOutput();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void pass1(String[] filenames) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Enter PROGADDR (hex): ");
        String progAddrStr = reader.readLine().trim();
        try {
            PROGADDR = progAddrStr.isEmpty() ? 0x4000 : Integer.parseInt(progAddrStr, 16);
        } catch (NumberFormatException e) {
            writeError("Invalid PROGADDR input: " + progAddrStr);
        }
        EXECADDR = PROGADDR;

        int currentAddr = PROGADDR;

        for (String filename : filenames) {
            ObjectProgram program = new ObjectProgram(filename);
            program.loadHeader();
            // Check for duplicate program name
            if (ESTAB.containsKey(program.programName)) {
                writeError("Duplicate external symbol: " + program.programName);
            }
            ESTAB.put(program.programName, currentAddr);
            program.setAddress(currentAddr);
            // Adjust definitions by adding currentAddr to their addresses
            Map<String, Integer> defs = program.getDefinitions();
            for (Map.Entry<String, Integer> entry : defs.entrySet()) {
                String symbol = entry.getKey();
                int addr = entry.getValue() + currentAddr;
                if (ESTAB.containsKey(symbol)) {
                    writeError("Duplicate external symbol: " + symbol);
                }
                ESTAB.put(symbol, addr);
            }
            currentAddr += program.programLength;
            objectPrograms.add(program);
        }
    }

    private static void pass2() throws IOException {
        // Initialize all memory as unused
        Arrays.fill(MEM_USED, false);
        
        for (ObjectProgram program : objectPrograms) {
            program.loadTextRecords();
            program.loadModificationRecords(ESTAB, MEM);
        }
    }

    private static void writeOutput() throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter("outfile.txt"));

        // Write ESTAB with control section information
        writer.write("Control Section  Address  Length\n");
        writer.write("----------------------------------------\n");
        
        // First write control sections
        for (ObjectProgram program : objectPrograms) {
            writer.write(String.format("%-15s %04X     %04X\n", 
                program.programName, 
                ESTAB.get(program.programName), 
                program.programLength));
            
            // Write external symbols for this control section
            for (Map.Entry<String, Integer> def : program.getDefinitions().entrySet()) {
                writer.write(String.format("  %-13s %04X\n", 
                    def.getKey(), 
                    ESTAB.get(def.getKey())));
            }
        }

        // Write Memory Contents
        writer.write("\nMemory Contents:\n");
        boolean hasContent = false;
        int lastAddr = -1;

        // Find the last address with content
        for (int i = MEM_SIZE - 1; i >= PROGADDR; i--) {
            if (MEM_USED[i]) {
                lastAddr = i;
                break;
            }
        }

        if (lastAddr == -1) lastAddr = PROGADDR;

        for (int i = PROGADDR; i <= lastAddr; i += 16) {
            StringBuilder line = new StringBuilder();
            line.append(String.format("%04X  ", i));
            boolean lineHasContent = false;

            for (int j = 0; j < 16; j += 4) {
                if (i + j + 3 < MEM_SIZE) {
                    StringBuilder group = new StringBuilder();
                    boolean groupHasContent = false;
                    
                    // Process each byte in the group
                    for (int k = 0; k < 4; k++) {
                        if (MEM_USED[i + j + k]) {
                            group.append(String.format("%02X", MEM[i + j + k] & 0xFF));
                            groupHasContent = true;
                        } else {
                            group.append("..");
                        }
                    }
                    
                    if (!groupHasContent) {
                        line.append("........  ");
                    } else {
                        line.append(group).append("  ");
                        lineHasContent = true;
                    }
                }
            }
            
            // Write the line if it has content or is the first line
            if (lineHasContent || i == PROGADDR) {
                writer.write(line.toString().trim() + "\n");
            }
        }

        // Write Program Counter
        writer.write(String.format("\nProgram Counter set to %04X\n", EXECADDR));

        writer.close();
    }

    public static void writeError(String message) throws IOException {
        System.err.println("Error: " + message); // Print to standard error
        BufferedWriter writer = new BufferedWriter(new FileWriter("outfile", true));
        writer.write("Error: " + message + "\n");
        writer.close();
        System.exit(1);
    }
}

class ObjectProgram {
    String filename;
    String programName;
    int programLength;
    int address;
    List<TextRecord> textRecords = new ArrayList<>();
    List<ModificationRecord> modificationRecords = new ArrayList<>();
    Map<String, Integer> definitions = new LinkedHashMap<>();

    public ObjectProgram(String filename) {
        this.filename = filename;
    }

    public void loadHeader() throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(filename));
        String line = br.readLine();
        if (line == null || !line.startsWith("H")) {
            siclink.writeError("Invalid header record in " + filename);
        }
        // Debugging: Print the header line
        System.out.println("Header Line: " + line);

        // Check if the line has enough length
        if (line.length() < 19) { // H + 6 (progname) + 6 (startaddr) + 6 (length) = 19
            siclink.writeError("Malformed header record: " + line);
        }

        // Parse Header Record: H^progname^startaddr^length
        programName = line.substring(1, 7).trim();
        String startAddrStr = line.substring(7, 13).trim();
        String lengthStr = line.substring(13).trim();

        // Debugging: Print parsed fields
        System.out.println("Program Name: " + programName);
        System.out.println("Start Address: " + startAddrStr);
        System.out.println("Program Length: " + lengthStr);

        try {
            address = Integer.parseInt(startAddrStr, 16);
            programLength = Integer.parseInt(lengthStr, 16);
        } catch (NumberFormatException e) {
            siclink.writeError("Invalid address or length in header record: " + line);
        }

        // Parse Definitions from D Records
        while ((line = br.readLine()) != null) {
            if (line.startsWith("D")) {
                // Debugging: Print the D record line
                System.out.println("Definition Record Line: " + line);
                // Each symbol is 6 chars: 6 for symbol, 6 for address
                for (int i = 1; i + 12 <= line.length(); i += 12) {
                    String symbol = line.substring(i, i + 6).trim();
                    String addrStr = line.substring(i + 6, i + 12).trim();
                    try {
                        definitions.put(symbol, Integer.parseInt(addrStr, 16));
                    } catch (NumberFormatException e) {
                        siclink.writeError("Invalid address in definition record: " + addrStr);
                    }
                }
            } else {
                break;
            }
        }
        br.close();
    }

    public void loadTextRecords() throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(filename));
        String line;
        // Skip Header and D Records
        while ((line = br.readLine()) != null) {
            if (!line.startsWith("H") && !line.startsWith("D")) {
                break;
            }
        }
        // Read Text Records
        while (line != null) {
            if (line.startsWith("T")) {
                TextRecord tr = new TextRecord(line);
                textRecords.add(tr);
            } else if (line.startsWith("M")) {
                ModificationRecord mr = new ModificationRecord(line);
                modificationRecords.add(mr);
            } else if (line.startsWith("E")) {
                // Process End Record
                if (line.length() > 1) {
                    // If there's an address specified in the End record
                    // Take characters 1-7 (after 'E') and trim whitespace
                    String addrStr = line.substring(1, Math.min(7, line.length())).trim();
                    if (!addrStr.isEmpty()) {
                        try {
                            int endAddr = Integer.parseInt(addrStr, 16);
                            siclink.EXECADDR = address + endAddr;  // Update EXECADDR
                        } catch (NumberFormatException e) {
                            siclink.writeError("Invalid address in End record: " + addrStr);
                        }
                    }
                }
                break;
            }
            line = br.readLine();
        }
        br.close();

        // Load Text Records into Memory
        for (TextRecord tr : textRecords) {
            int start = address + tr.getStartAddress();
            for (int i = 0; i < tr.getObjectCodes().size(); i++) {
                String obj = tr.getObjectCodes().get(i);
                try {
                    byte b = (byte) Integer.parseInt(obj, 16);
                    if (start + i < siclink.MEM_SIZE) {
                        siclink.MEM[start + i] = b;
                        siclink.MEM_USED[start + i] = true;
                    } else {
                        siclink.writeError("Memory overflow while loading " + filename);
                    }
                } catch (NumberFormatException e) {
                    siclink.writeError("Invalid object code '" + obj + "' in " + filename);
                }
            }
        }
    }

    public void loadModificationRecords(Map<String, Integer> ESTAB, byte[] MEM) throws IOException {
        for (ModificationRecord mr : modificationRecords) {
            String symbol = mr.getSymbol();
            System.out.println("Processing Modification Record for Symbol: " + symbol);
            if (!ESTAB.containsKey(symbol)) {
                siclink.writeError("Undefined external symbol: " + symbol);
            }
            int symbolAddr = ESTAB.get(symbol);
            int modAddr = address + mr.getModifyAddress();
            // Read the existing 3-byte address from memory
            int original = ((MEM[modAddr] & 0xFF) << 16) | ((MEM[modAddr + 1] & 0xFF) << 8) | (MEM[modAddr + 2] & 0xFF);
            // Apply modification based on the sign
            int modified = mr.isAddition() ? original + symbolAddr : original - symbolAddr;
            // Write back the modified address to memory
            MEM[modAddr] = (byte) ((modified >> 16) & 0xFF);
            MEM[modAddr + 1] = (byte) ((modified >> 8) & 0xFF);
            MEM[modAddr + 2] = (byte) (modified & 0xFF);
            System.out.println("Modified Address " + String.format("%06X", modAddr) + " from " + String.format("%06X", original) + " to " + String.format("%06X", modified));
        }
    }

    public Map<String, Integer> getDefinitions() {
        return definitions;
    }

    public void setAddress(int address) {
        this.address = address;
    }
}

class TextRecord {
    int startAddress;
    List<String> objectCodes = new ArrayList<>();

    public TextRecord(String record) {
        // T^startaddr^length^objcode
        if (record.length() < 9) { // Minimum expected length
            try {
                siclink.writeError("Malformed T record: " + record);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        String startAddrStr = record.substring(1, 7).trim();
        String lengthStr = record.substring(7, 9).trim();
        try {
            startAddress = Integer.parseInt(startAddrStr, 16);
        } catch (NumberFormatException e) {
            try {
                siclink.writeError("Invalid start address in T record: " + startAddrStr);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        try {
            int length = Integer.parseInt(lengthStr, 16);
            // Length is not used in this implementation but can be utilized if needed
        } catch (NumberFormatException e) {
            try {
                siclink.writeError("Invalid length in T record: " + lengthStr);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        if (record.length() > 9) {
            String objCodeStr = record.substring(9).trim();
            for (int i = 0; i < objCodeStr.length(); i += 2) {
                if (i + 2 <= objCodeStr.length()) {
                    objectCodes.add(objCodeStr.substring(i, i + 2));
                } else {
                    // Pad with '0' if incomplete byte
                    objectCodes.add(objCodeStr.substring(i) + "0");
                }
            }
        }
    }

    public int getStartAddress() {
        return startAddress;
    }

    public List<String> getObjectCodes() {
        return objectCodes;
    }
}

class ModificationRecord {
    String symbol;
    int modifyAddress;
    boolean isAddition; // true for '+', false for '-'

    public ModificationRecord(String record) {
        // M^modify_address^length^+symbol or -symbol
        if (record.length() < 10) { // Adjusted length to accommodate sign and symbol
            try {
                siclink.writeError("Malformed M record: " + record);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        String modifyAddrStr = record.substring(1, 7).trim();
        String lengthStr = record.substring(7, 9).trim(); // Length can be used if needed
        String sign = record.substring(9, 10).trim();
        String symbol = record.substring(10).trim();
        try {
            modifyAddress = Integer.parseInt(modifyAddrStr, 16);
        } catch (NumberFormatException e) {
            try {
                siclink.writeError("Invalid modify address in M record: " + modifyAddrStr);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        this.symbol = symbol;
        this.isAddition = sign.equals("+");
    }

    public String getSymbol() {
        return symbol;
    }

    public int getModifyAddress() {
        return modifyAddress;
    }

    public boolean isAddition() {
        return isAddition;
    }
} 