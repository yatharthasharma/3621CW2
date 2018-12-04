package uk.ac.ncl.undergraduate.modules.csc3621.paillier;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

/**
 * This class implements the algorithms in the Paillier scheme.
 *
 * @author Changyu Dong
 * @author Yathartha Sharma
 */

public class PaillierScheme {
	
	/**
	 * The key generation algorithm.
	 * @param n determines the bit length of prime numbers p and q, i.e |p| = |q| = n.
	 * @return a valid public private key pair in Paillier scheme.
	 */
	public static KeyPair Gen(int n) {
		BigInteger p = BigInteger.probablePrime(n, new SecureRandom());
		BigInteger q = BigInteger.probablePrime(n, new SecureRandom());
		BigInteger N = p.multiply(q);
		BigInteger NSqr = N.multiply(N);
		BigInteger phiN = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		PublicKey pk = new PublicKey(N, NSqr);
		PrivateKey sk = new PrivateKey(N, NSqr, phiN);
		return new KeyPair(pk, sk);
	}
	
	/**
	 * The encryption algorithm
	 * @param pk the public key
	 * @param m the plaintext to be encrypted
	 * @return the ciphertext of m
	 */
	// stop thru the iterating in bw and choose any of the big ints that you have at that point
	public static BigInteger Enc(PublicKey pk, BigInteger m) {
		ArrayList<BigInteger> x = new ArrayList<>();
		for (long i = 0; i < m.longValue(); i++){
			if (m.gcd(BigInteger.valueOf(i)) == BigInteger.ONE){
				x.add(BigInteger.valueOf(i));
			}
		}
		int r = x.get(new SecureRandom().nextInt(x.size())).intValue();
		BigInteger N = pk.getN();
		BigInteger NSqr = pk.getNSqr();
		long l = (long) r;
		return ((BigInteger.ONE.add(N)).modPow(m, BigInteger.ONE)).multiply(BigInteger.valueOf(l).modPow(N, NSqr));
	}
	
	/**
	 * The decryption algorithm
	 * @param sk the private key
	 * @param c the ciphertext to be decrypted
	 * @return the plaintext decrypted from c
	 */
	public static BigInteger Dec(PrivateKey sk, BigInteger c) {
		BigInteger a = c.modPow(sk.getPhiN(), sk.getNSqr());
		BigInteger b = (a.subtract(BigInteger.ONE)).divide(sk.getN());
		return b.multiply(sk.getPhiN().modInverse(sk.getN()));
	}
	
	/**
	 * The homomorphic addition algorithm
	 * @param pk the public key
	 * @param c1 the first ciphertext
	 * @param c2 the second ciphertext
	 * @return the ciphertext contains the addition result
	 */
	public static BigInteger Add(PublicKey pk, BigInteger c1, BigInteger c2) {
		return (c1.multiply(c2)).mod(pk.getNSqr());
	}
	
	/**
	 * The homomorphic multiply with plaintext algorithm
	 * @param pk the public key
	 * @param s a plaintext integer
	 * @param c the ciphertext
	 * @return the ciphertext contains the multiplication result
	 */
	
	public static BigInteger Multiply(PublicKey pk, BigInteger s, BigInteger c) {
		return (c.modPow(s, pk.getNSqr()));
	}
	

}
