package uk.ac.ncl.undergraduate.modules.csc3621.paillier;

import java.math.BigInteger;
/**
 * This class represents a public key in the Paillier scheme. It merely stores the key.
 * The key should be generated externally.
 *
 * @author Changyu Dong
 */
public class PublicKey {
	
	/**
	 * Integer N = p*q where p and q are two big prime numbers
	 */
	private BigInteger N;
	
	/**
	 * Integer NSqr = N^2
	 */
	private BigInteger NSqr;
	
	public PublicKey(BigInteger N,BigInteger NSqr) {
		this.N = N;
		this.NSqr = NSqr;
	}

	public void setKey(BigInteger N,BigInteger NSqr) {
		this.N = N;
		this.NSqr = NSqr;
	}
	
	public BigInteger getN() {
		return this.N;
	}
	
	
	public BigInteger getNSqr() {
		return this.NSqr;
	}
	
}
