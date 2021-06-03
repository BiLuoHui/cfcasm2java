public class Main {
    public static void main(String[] args) {
        String x = "021091496615CF1C69B631D393C68BECCAFCCEAC5527667E95328F8ABF5CF5A4";
        String y = "03A2A7B640E67E861B336FC7589486257A7D841159D11696C3F4296E0F21A0D5";
        String d = "7CD798AF4F6643E844591902569A4E35514A21E9866D537892115AC21494C550";

        SM2 clz = SM2.getInstance();
        byte[] sourceData = "userData".getBytes();
        {
            // 自签自验
            System.out.println("=========================自签自验==================================");
            byte[] sign = clz.SM2Sign(hexStringToBytes(d), sourceData);
            System.out.println("sign data: " + new String(sign));
            boolean verify = clz.SM2Verify(hexStringToBytes(x), hexStringToBytes(y), sourceData, sign);
            System.out.println("verify result: " + verify);
        }

        {
            // 验证go生成的签名数据
            System.out.println("=========================验证go生成的签名数据==================================");
            byte[] sign = "MEQgIHf2Ulg2rsh1RXltLab/uIBJ6qWQn4N1AQlJfHSsITRGAiCLPVz7uaX0HuT6Pba+2PiUYmXDhT+cBpd+uT8LSPHgNQ==".getBytes();
            boolean verify = clz.SM2Verify(hexStringToBytes(x), hexStringToBytes(y), sourceData, sign);
            System.out.println("go verify result: " + verify);
        }
    }

    private static byte charToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }

    private static byte[] hexStringToBytes(String hexString) {
        if (hexString == null || hexString.equals("")) {
            return null;
        }
        hexString = hexString.toUpperCase();
        int length = hexString.length() / 2;
        char[] hexChars = hexString.toCharArray();
        byte[] d = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i * 2;
            d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
        }
        return d;
    }
}
