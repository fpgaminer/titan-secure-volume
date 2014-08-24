Titan Secure Volume
===================

Introduction
------------

A Titan Secure Volume is an encrypted, authenticated, and redundant block device.  It is designed for use by the Titan Device, but should be flexible enough to find use in other applications.  Each block (called Sector in TSV) is processed individually, Encrypt-then-MAC, and uses a Sector specific Tweak on both the encryption and the authentication to frustrate modification of the volume by an attacker.  All data is replicated, so that if one copy becomes corrupted, the other can be used to read the original data.

Sector size is specified when the volume is created, allowing the volume to be adapted to the underlying storage block size, and the application's performance characteristics.  Larger sectors use more RAM, but require less frequent cipher passes if disk access is coalesced.  Smaller sectors use less RAM, but require less frequency cipher passes if disk access is fragmented.

The volume consists of a Header, a MAC table, the Sectors, and then a copy of the MAC table and Sectors.  Everything is either encrypted data, MAC tags, or random data.  Therefore, the entire TSV is indistinguishable from noise without its associated keys.

Titan Secure Volume can store a theoretical maximum of ~8 exbibytes of data (Sector Size: 0xFFFFFFFF, Sector Count: 0x7FFFFFFF).



Data Format
-----------

Always starts with a Volume Header, padded to 1 Sector.  Followed by a MAC Table, padded to a multiple of Sector Size.  Followed by 0 or more Sectors.  After that is a copy of the MAC Table and Sectors for redundancy.  The redundant data is stored after the original data, rather than interwoven, so that it is likely at a physically different part of the underlying disk.

All structures in a Titan Secture Volume follow the Encrypt-then-MAC pattern.  Data should always be authenticated before being fed into the decryption function(s).

All integer values are stored little endian.

The Volume Header and Sectors are authenticated using their associated MAC tags.  MAC should be tweaked using sector number, where the header is considered tweak 0, and the first sector is tweak 1.  The same tweak values apply to encryption.

Note that Sector Count cannot exceed 0x7FFFFFFF.  The upper most bit may be used by libraries to distinguish between copies of a Sector.



Cryptography
------------

Since the Volume Header is encrypted, there is no way to specify the cipher suite in use by a volume.  Support for different cipher suites (Encryption function + Authentication function) is achieved by attempting to read the header using all possible cipher suites.  If all fail, either the keys are wrong, the volume is either not a TSV, the volume is corrupted, or the volume uses an unknown cipher suite.  Below are listed the officially "supported" cipher suites.


Version 0x0100:

	* Suite Threefish-512-XTS:HMAC-SHA-256
		- 64 byte MAC Key
		- 64 byte Encryption Key
		- Authentication: HMAC-SHA-256
		- Encryption: Threefish-512-XTS
		- tag = MAC (MAC Key, data || tweak)
		- Volume Header Tweak is 0.
		- Sector Tweak is Sector Number + 1 (first sector's tweak is 1).
	
Version 0x0100 supports only Threefish.  Threefish-512-XTS was chosen for its modern approach, simplicity of the algorithm, resistance to side channel attacks, and native support for Tweaks.


Support for integrity checks can be tacked on to a TSV by including a HASH of its header (Encrypt-then-MAC-then-HASH).  This would allow a library to differentiate between a corrupted volume and bad keys.  Of course, this defeats the indistinguishable (from noise) property of a native TSV.



Data Structures
---------------

Volume Header:

	* 8   string    "TITANTSV"
	* 2   uint16    Version (0x0100)
	* 4   uint32    Sector Size in bytes
	* 4   uint32    Sector Count
	* 46            Padding (Make Header Data Multiple of 64)
	* 32  binary    MAC tag
	* *             Padding (Make Header Multiple of Sector Size)

The Volume Header, including MAC tag and the last Padding, must be 1 Sector in size.
The MAC tag authenticates the entire header, except for the last Padding and the MAC tag itself.
Padding must be filled with random data.
The first Padding is encrypted, but the last Padding is not.


MAC Table:

	* Tag Size*Sector Count   binary    MAC tag(s)
	* *                                 Padding

The MAC Table follows the Volume Header, and must be padded such that its length is a multiple of Sector Size.
The MAC Table has no associated MAC tag, as it is not necessary to authenticate the MAC tags themselves.
The MAC Table is not encrypted.
The Padding must be filled with random data.


Sector:

	* 1*Sector Size           binary    Data

The Sector is associated with a MAC tag using the MAC Table.  The first sector corresponds with the first MAC tag in the MAC Table, and so on.




Recommendations for Implementations
-------------------------------------------

When writing a Sector, always overwrite the damaged copy of the old sector, if one exists.  For example, to overwrite part of a sector, the entire sector must be read into memory, auth'd, decrypted, modified, encrypted, auth'd, and written back out.  Thus, if power-loss occurs or the underlying disk fails to complete the write, the entire sector may become corrupted.  Overwriting any previously corrupted copies of the sector first will ensure that a valid copy still exists if such events happen.

Implementations may choose to read sector copies randomly.  i.e. if the application reads from Sector 0, the library may choose to read from either the first or second copy of Sector 0.  Doing this randomly, instead of deterministically, will efficiently discover corruption.  The library may choose to then repair the corruption, if the other copy of the sector is valid.

Implementations should implement cache primarily at the TSV level.  In other words, the TSV implementation should cache its decrypted sectors.  As opposed to caching at the underlying disk level, which would certainly avoid disk access but would not avoid cipher cost.  Note that the TSV cache should include a special cache of the MAC table (or pieces of it).
