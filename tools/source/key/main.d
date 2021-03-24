/*******************************************************************************

   A simple cli tool to sign, generate random keypairs, and verify signatures

   Doubles as a documentation for functions' API.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module key.main;

import std.algorithm;
import std.ascii;
import std.conv;
import std.digest.crc;
import std.encoding;
import std.getopt;
import std.range;
import std.stdio;
import std.string;

import libsodium;

import stellar.sdk.key;

/// Entry point
int main (string[] args)
{
    if (sodium_init() < 0)
    {
        writeln("Error initializing libsodium");
        return 1;
    }

    if (args.length < 2)
    {
        writeln("Error: Expected one of: generate, pubkey, sign, verify");
        return 1;
    }

    switch (args[1])
    {
    case "generate":
        KeyPair kp = KeyPair.random();
        writeln("Private seed:    ", kp.seed.toString());
        writeln("Public address:  ", kp.address.toString());
        break;

    case "pubkey":
        if (args.length < 3)
        {
            writeln("Error: Expected 'pubkey $SEED`");
            return 1;
        }
        KeyPair kp = KeyPair.fromSeed(Seed.fromString(args[2]));
        writeln("Private seed:    ", kp.seed.toString());
        writeln("Public address:  ", kp.address.toString());
        break;

    case "sign":
        if (args.length < 4 || !args[3].length)
        {
            writeln("Error: Expected 'sign $SEED $MESSAGE`");
            return 1;
        }
        KeyPair kp = KeyPair.fromSeed(Seed.fromString(args[2]));
        scope msg = args[3].representation;
        scope res = kp.secret.sign(msg);
        {
            scope ret = kp.address.verify(res);
            assert(ret == msg);
        }
        writeln("Signed message: ", toHexString(res));
        break;

    case "verify":
        if (args.length < 4)
        {
            writeln("Error: Expected 'verify $PUBLICKEY $SIGNATURE`");
            return 1;
        }
        PublicKey pubkey = PublicKey.fromString(args[2]);
        scope msg = args[3].chunks(2).map!(
            twoDigits => twoDigits.parse!ubyte(16))
                        .array();
        scope result = pubkey.verify(msg);
        if (result.length == 0)
        {
            writeln("Verification failed");
            return 1;
        }
        writeln("Result: ", toHexString(result));

        auto str = cast(const(char)[])result;
        if (isValid(str))  // we don't want to emit binary data as a string
            writeln("Result as string: ", str);
        break;

    default:
        writeln("Error: Unknown command ", args[1], ". Expected one of: generate, pubkey, sign, verify");
        return 1;
    }

    return 0;
}
