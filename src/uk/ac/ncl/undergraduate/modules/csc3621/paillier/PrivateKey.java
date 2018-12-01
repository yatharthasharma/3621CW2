package uk.ac.ncl.undergraduate.modules.csc3621.paillier;

import java.math.BigInteger;

/**
 * This class represents a private key in the Paillier scheme. It merely stores the key.
 * The key should be generated externally.
 *
 * @author Changyu Dong
 */

public class PrivateKey {
	
	/**
	 * Integer N = p*q where p and q are two big prime numbers
	 */
	private BigInteger N;
	/**
	 * Integer NSqr = N^2
	 */
	private BigInteger NSqr;
	/**
	 * Integer phiN = (p-1)(q-1)
	 */
	private BigInteger phiN;
	

	public PrivateKey(BigInteger N, BigInteger NSqr, BigInteger phiN) {
		this.N=N;
		this.NSqr=NSqr;
		this.phiN=phiN;
	}
	

	
	public void setKey(BigInteger N, BigInteger NSqr, BigInteger phiN) {
		this.N=N;
		this.NSqr=NSqr;
		this.phiN=phiN;
	}
	

	
	public BigInteger getN() {
		return this.N;
	}


	public BigInteger getNSqr() {
		return this.NSqr;
	}

	public BigInteger getPhiN() {
		return this.phiN;
	}
}
