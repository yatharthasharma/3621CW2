package uk.ac.ncl.undergraduate.modules.csc3621.paillier;

/**
 * This class represents a public/private key pair. It merely stores the keys.
 * The keys should be generated externally.
 *
 * @author Changyu Dong
 */

public class KeyPair {
	 /**
     * The public key in the pair.
     */
	private PublicKey pk;
	 /**
     * The private key in the pair.
     */
	private PrivateKey sk;
	

	public KeyPair(PublicKey pk, PrivateKey sk) {
		this.pk=pk;
		this.sk=sk;
	}
	

	
	public void setPublicKey(PublicKey pk) {
		this.pk=pk;
	}
	

	public void setPrivateKey(PrivateKey sk) {
		this.sk=sk;
	}
	

	public PublicKey getPublicKey() {
		return this.pk;
	}
	

	public PrivateKey getPrivateKey() {
		return this.sk;
	}

}
