package it.auties.leap.codegen;

import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class Test {
    public static void main(String[] args) throws IOException {
        System.out.println(new String(getPubSuffixStream().readAllBytes()));
    }

    private static InputStream getPubSuffixStream() throws IOException {
        InputStream is = null;
        File f = new File(System.getProperty("java.home"),
                "lib/security/public_suffix_list.dat");
        try {
            is = new FileInputStream(f);
        } catch (FileNotFoundException e) { }
        if (is == null) {

        }
        var zis = new ZipInputStream(is);
        boolean found = false;
        ZipEntry ze = zis.getNextEntry();
        while (ze != null && !found) {
            if (ze.getName().equals("org")) {
                found = true;
            } else {
                ze = zis.getNextEntry();
            }
        }
        if (!found) {
            return null;
        }
        return is;
    }
}
