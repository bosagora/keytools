/*******************************************************************************

    Hold primitive types for key operations

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module stellar.sdk.key;

import stellar.sdk.crc16;

import geod24.BitBlob;
import base32;
import libsodium;

import std.exception : assumeUnique;


// Can't let them have the same type
static assert(PublicKey.Width != SecretKey.Width);

/// A structure to hold a secret key + public key + seed
/// Can be constructed from a seed
/// To construct addresses (PublicKey), see `addressFromString`
public struct KeyPair
{
    /// Constructor accepting only 3 arguments
    private this (typeof(KeyPair.tupleof) args)
    {
        this.tupleof = args;
    }

    /// Secret key
    public const PublicKey address;
    public const SecretKey secret;
    public const Seed      seed;

    /// Create a keypair from a `Seed`
    public static KeyPair fromSeed (Seed seed)
    {
        SecretKey sk;
        PublicKey pk;
        if (crypto_sign_seed_keypair(pk[].ptr, sk[].ptr, seed[].ptr) != 0)
            assert(0);
        return KeyPair(pk, sk, seed);
    }

    /// Generate a new, random, keypair
    public static KeyPair random ()
    {
        SecretKey sk;
        PublicKey pk;
        Seed seed;
        if (crypto_sign_keypair(pk[].ptr, sk[].ptr) != 0)
            assert(0);
        if (crypto_sign_ed25519_sk_to_seed(seed[].ptr, sk[].ptr) != 0)
            assert(0);
        return KeyPair(pk, sk, seed);
    }
}


/// Represent a public key / address
public struct PublicKey
{
    /// Constructor accepting only 1 argument
    private this (typeof(PublicKey.tupleof) args)
    {
        this.tupleof = args;
    }

    /*private*/ BitBlob!(crypto_sign_PUBLICKEYBYTES * 8) data;
    alias data this;

    /// Uses Stellar's representation instead of hex
    public string toString () const
    {
        ubyte[1 + PublicKey.Width + 2] bin;
        bin[0] = VersionByte.AccountID;
        bin[1 .. $ - 2] = this.data[];
        bin[$ - 2 .. $] = checksum(bin[0 .. $ - 2]);
        return Base32.encode(bin).assumeUnique;
    }

    /// Make sure the sink overload of BitBlob is not picked
    public void toString (scope void delegate(const(char)[]) sink) const
    {
        ubyte[1 + PublicKey.Width + 2] bin;
        bin[0] = VersionByte.AccountID;
        bin[1 .. $ - 2] = this.data[];
        bin[$ - 2 .. $] = checksum(bin[0 .. $ - 2]);
        sink(Base32.encode(bin));
    }

    /// Create a Seed from Stellar's string representation
    public static PublicKey fromString (scope const(char)[] str)
    {
        const bin = Base32.decode(str);
        assert(bin.length == 1 + PublicKey.Width + 2);
        assert(bin[0] == VersionByte.AccountID);
        assert(validate(bin[0 .. $ - 2], bin[$ - 2 .. $]));
        return PublicKey(typeof(this.data)(bin[1 .. $ - 2]));
    }

    /// Expose verification capability
    public const(ubyte)[] verify (scope const(ubyte)[] msg) const
    {
        if (msg.length < crypto_sign_ed25519_BYTES)
            return null;

        ubyte[] res = new ubyte[](msg.length - crypto_sign_ed25519_BYTES);
        size_t reslen;
        if (crypto_sign_ed25519_open(res.ptr, &reslen, msg.ptr, msg.length, this.data[].ptr) != 0)
            return null;
        return res[0 .. reslen];
    }
}


/// A secret key.
/// Since we mostly expose seed and public key to the user,
/// this does not expose any Stellar serialization shenanigans.
public struct SecretKey
{
    /// Constructor accepting only 1 argument
    private this (typeof(this.tupleof) args)
    {
        this.tupleof = args;
    }

    /*private*/ BitBlob!(crypto_sign_ed25519_SECRETKEYBYTES * 8) data;
    alias data this;

    /// Expose signing capability
    public const(ubyte)[] sign (scope const(ubyte)[] msg) const
    {
        ubyte[] res = new ubyte[](crypto_sign_ed25519_BYTES + msg.length);
        size_t reslen;
        if (crypto_sign_ed25519(res.ptr, &reslen, msg.ptr, msg.length, this.data[].ptr) != 0)
            assert(0);
        return res[0 .. reslen];
    }
}


/// A Stellar seed
public struct Seed
{
    /// Constructor accepting only 1 argument
    private this (typeof(Seed.tupleof) args)
    {
        this.tupleof = args;
    }

    /*private*/ BitBlob!(crypto_sign_SEEDBYTES * 8) data;
    alias data this;

    /// Uses Stellar's representation instead of hex
    public string toString () const
    {
        ubyte[1 + Seed.Width + 2] bin;
        bin[0] = VersionByte.Seed;
        bin[1 .. $ - 2] = this.data[];
        bin[$ - 2 .. $] = checksum(bin[0 .. $ - 2]);
        return Base32.encode(bin).assumeUnique;
    }

    /// Make sure the sink overload of BitBlob is not picked
    public void toString (scope void delegate(const(char)[]) sink) const
    {
        ubyte[1 + Seed.Width + 2] bin;
        bin[0] = VersionByte.Seed;
        bin[1 .. $ - 2] = this.data[];
        bin[$ - 2 .. $] = checksum(bin[0 .. $ - 2]);
        sink(Base32.encode(bin));
    }

    /// Create a Seed from Stellar's string representation
    public static Seed fromString (scope const(char)[] str)
    {
        const bin = Base32.decode(str);
        assert(bin.length == 1 + Seed.Width + 2);
        assert(bin[0] == VersionByte.Seed);
        assert(validate(bin[0 .. $ - 2], bin[$ - 2 .. $]));
        return Seed(typeof(this.data)(bin[1 .. $ - 2]));
    }
}

public enum VersionByte : ubyte
{
	/// Used for encoded stellar addresses
    /// Base32-encodes to 'G...'
	AccountID = 6 << 3,
	/// Used for encoded stellar seed
    /// Base32-encodes to 'S...'
	Seed = 18 << 3,
	/// Used for encoded stellar hashTx signer keys.
    /// Base32-encodes to 'T...'
	HashTx = 19 << 3,
	/// Used for encoded stellar hashX signer keys.
    /// Base32-encodes to 'X...'
	HashX = 23 << 3,
}

bool isValidVersionByte (ubyte vb)
{
    return vb == VersionByte.AccountID
        || vb == VersionByte.Seed
        || vb == VersionByte.HashTx
        || vb == VersionByte.HashX;
}
