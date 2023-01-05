package com.example.flowwallet;

public class ByteUtils {
    public static byte[] combineByte(byte[] first, byte[] second){
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first,0,result,0,first.length);
        System.arraycopy(second,0,result,first.length,second.length);
        return result;
    }
}
