import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * SM2withSM3 签名工具
 */
public class SM2 {
    // 设置默认椭圆曲线参数(P A B N Gx Gy), 以下设置表示采用国密7号曲线
    private static final BigInteger a = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
    private static final BigInteger b = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
    private static final BigInteger gx = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
    private static final BigInteger gy = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
    private static final BigInteger n = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
    private static final BigInteger p = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);

    // SM3运算的初始化向量,国密标准固定为"1234567812345678"
    private static final String USER_ID = "1234567812345678";

    private final ECCurve eccCure;
    private final ECPoint eccPointG;
    private final ECKeyPairGenerator eccKeyPairGenerator;

    /**
     * 构造方法,通过国密7号曲线参数设置BC包的实例
     */
    private SM2() {
        ECFieldElement eccGxFieldelement = new ECFieldElement.Fp(SM2.p, SM2.gx);
        ECFieldElement eccGyFieldelement = new ECFieldElement.Fp(SM2.p, SM2.gy);
        this.eccCure = new ECCurve.Fp(SM2.p, SM2.a, SM2.b);
        this.eccPointG = new ECPoint.Fp(this.eccCure, eccGxFieldelement, eccGyFieldelement);
        ECDomainParameters eccBcSpec = new ECDomainParameters(this.eccCure, this.eccPointG, SM2.n);
        ECKeyGenerationParameters eccEcgenparam = new ECKeyGenerationParameters(eccBcSpec, new SecureRandom());
        this.eccKeyPairGenerator = new ECKeyPairGenerator();
        this.eccKeyPairGenerator.init(eccEcgenparam);
    }

    public static SM2 getInstance() {
        return new SM2();
    }

    /**
     * 计算Z值,该值将参与业务数据的SM3运算
     *
     * @param userId  初始化向量
     * @param userKey 公钥数据,计算Z值需要SM2公钥x/y参与运算
     * @return 返回Z值
     */
    private byte[] sm2GetZ(byte[] userId, ECPoint userKey) {
        SM3Digest sm3 = new SM3Digest();

        // 初始化向量长度和初始化数据参与Z值的计算
        int len = userId.length * 8;
        sm3.update((byte) (len >> 8 & 0xFF));
        sm3.update((byte) (len & 0xFF));
        sm3.update(userId, 0, userId.length);

        // 公钥x/y和椭圆曲线参数参与Z值的计算,数据(A B Gx Gy x y)长度固定32字节
        // 当数据第一个字节大于0x80时BigInteger自动补0x00, 所以取后32字节有效数据
        byte[] p = SM2.a.toByteArray();
        sm3.update(p, p.length - 32, 32);
        p = SM2.b.toByteArray();
        sm3.update(p, p.length - 32, 32);
        p = SM2.gx.toByteArray();
        sm3.update(p, p.length - 32, 32);
        p = SM2.gy.toByteArray();
        sm3.update(p, p.length - 32, 32);
        p = userKey.normalize().getXCoord().toBigInteger().toByteArray();
        sm3.update(p, p.length - 32, 32);
        p = userKey.normalize().getYCoord().toBigInteger().toByteArray();
        sm3.update(p, p.length - 32, 32);

        // 得到最终的Z值结果,整个过程是对初始化向量/公钥/椭圆曲线参数进行SM3运算
        byte[] md = new byte[sm3.getDigestSize()];
        sm3.doFinal(md, 0);
        return md;
    }

    /**
     * SM2签名运算,使用私钥对业务数据哈希值进行签名运算
     *
     * @param md    业务数据哈希值
     * @param userD SM2私钥
     * @return SM2签名数据R/S
     */
    private BigInteger[] sm2Sign(byte[] md, BigInteger userD) {
        BigInteger e = new BigInteger(1, md);
        BigInteger k;
        ECPoint kp;
        BigInteger r;
        BigInteger s;

        do {
            do {
                AsymmetricCipherKeyPair keyPair = eccKeyPairGenerator.generateKeyPair();
                ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keyPair.getPrivate();
                ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keyPair.getPublic();
                k = ecpriv.getD();
                kp = ecpub.getQ();
                r = e.add(kp.getXCoord().toBigInteger());
                r = r.mod(SM2.n);
            } while (r.equals(BigInteger.ZERO) || r.add(k).equals(SM2.n) || r.toString(16).length() != 64);
            BigInteger da_1 = userD.add(BigInteger.ONE);
            da_1 = da_1.modInverse(SM2.n);

            s = r.multiply(userD);
            s = k.subtract(s).mod(SM2.n);
            s = da_1.multiply(s).mod(SM2.n);
        } while (s.equals(BigInteger.ZERO) || (s.toString(16).length() != 64));
        return new BigInteger[]{r, s};
    }

    /**
     * SM2验签运算,使用公钥对业务数据哈希值进行验证运算
     *
     * @param md      业务数据哈希值
     * @param userKey SM2公钥
     * @param r       SM2签名数据R
     * @param s       SM2签名数据S
     * @return 验签成功返回true, 否则返回false
     */
    private boolean sm2Verify(byte[] md, ECPoint userKey, BigInteger r, BigInteger s) {
        BigInteger e = new BigInteger(1, md);
        BigInteger t = r.add(s).mod(SM2.n);
        if (t.equals(BigInteger.ZERO)) {
            return false;
        }
        ECPoint x1y1 = eccPointG.multiply(s);
        x1y1 = x1y1.add(userKey.multiply(t));
        BigInteger R = e.add(x1y1.normalize().getXCoord().toBigInteger()).mod(SM2.n);
        return r.equals(R);
    }

    /**
     * 将SM2签名数据R/S转化为DER编码
     *
     * @param R SM2签名数据R
     * @param S SM2签名数据S
     * @return DER编码后的SM2签名数据
     */
    private byte[] encodeDer(BigInteger R, BigInteger S) {
        byte[] r = R.toByteArray();
        byte[] s = S.toByteArray();

        int rLen = r.length;
        int sLen = s.length;

        // SM2签名值的DER编码格式(0x30 + 数据总长度 + 0x02 + R的长度 + R + 0x02 + S的长度 + S
        byte[] der = new byte[6 + rLen + sLen];
        der[0] = 0x30;
        der[1] = (byte) (4 + rLen + sLen);
        der[2] = 0x20;
        der[3] = (byte) rLen;
        System.arraycopy(r, 0, der, 4, rLen);
        der[4 + rLen] = 0x02;
        der[5 + rLen] = (byte) sLen;
        System.arraycopy(s, 0, der, 6 + rLen, sLen);
        return der;
    }

    /**
     * 将DER编码的SM2签名转化为数据R/S
     *
     * @param der SM2签名
     * @return 数据R/S
     */
    private BigInteger[] decodeDer(byte[] der) {
        int rLen = der[3];
        byte[] r = new byte[rLen];
        System.arraycopy(der, 4, r, 0, rLen);

        int sLen = der[5 + rLen];
        byte[] s = new byte[sLen];
        System.arraycopy(der, 6 + rLen, s, 0, sLen);

        BigInteger[] RS = new BigInteger[2];
        RS[0] = new BigInteger(1, r);
        RS[1] = new BigInteger(1, s);

        return RS;
    }


    /**
     * SM2withSM3签名
     *
     * @param d          SM2私钥D（32字节）
     * @param sourceData 业务数据
     * @return DER+Base64编码后的签名结果
     */
    public byte[] SM2Sign(byte[] d, byte[] sourceData) {
        // 将byte[]类型的私钥数据转化为ECPoint实例
        BigInteger userD = new BigInteger(1, d);
        ECPoint userPriKey = eccPointG.multiply(userD);

        // 通过初始化向量和密钥计算SM3的Z值
        byte[] md = sm3Digest(sourceData, userPriKey);

        // 进行SM2签名,将签名值R/S进行DER编码和Base64编码后返回
        BigInteger[] rs = sm2Sign(md, userD);
        byte[] sign = encodeDer(rs[0], rs[1]);
        return Base64.getEncoder().encode(sign);
    }

    /**
     * SM2withSM3验证
     *
     * @param x          SM2公钥X
     * @param y          SM2公钥Y
     * @param sourceData 业务数据
     * @param signData   DER+Base64编码后的签名结果
     * @return true验签通过/false验签失败
     */
    public boolean SM2Verify(byte[] x, byte[] y, byte[] sourceData, byte[] signData) {
        // 对公钥x/y进行DER编码,格式为(0x04 + x + y)
        byte[] publicKey = new byte[65];
        publicKey[0] = 0x04;
        // source array,source array start index,destination array,destination start index,copy length
        System.arraycopy(x, 0, publicKey, 1, 32);
        System.arraycopy(y, 0, publicKey, 33, 32);

        // 将byte[]类型的公钥数据转化为ECPoint实例
        ECPoint userPubKey = eccCure.decodePoint(publicKey);
        byte[] md = sm3Digest(sourceData, userPubKey);

        // 将SM2签名值进行Base64解码和DER解码,得到签名值R/S
        byte[] signDataAsn1 = Base64.getDecoder().decode(signData);
        BigInteger[] rs = decodeDer(signDataAsn1);

        // 进行SM2验签,验签通过返回true
        return sm2Verify(md, userPubKey, rs[0], rs[1]);
    }

    /**
     * 获取数据的SM3摘要
     *
     * @param sourceData 需要加密的数据
     * @param userPubKey SM2 私钥
     * @return digestBytes
     */
    private byte[] sm3Digest(byte[] sourceData, ECPoint userPubKey) {
        // 通过初始化向量和密钥计算SM3的Z值
        byte[] z = sm2GetZ(USER_ID.getBytes(), userPubKey);

        // 通过Z值计算用户数据的哈希值
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(z, 0, z.length);
        sm3Digest.update(sourceData, 0, sourceData.length);
        byte[] digestBytes = new byte[32];
        sm3Digest.doFinal(digestBytes, 0);
        return digestBytes;
    }
}
