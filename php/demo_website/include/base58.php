<?php

//
// Decode a "base58check" address into its parts: one-byte version, 20-byte hash, 4-byte checksum.
// Based on code from Jeff Garziks picocoin project.
//
// Returns either false or an array with (version, hash, checksum)
// Relies on bcmath to do the heavy lifting.
//
function decode_base58($btcaddress)
{
    // Compute big base58 number:
    $chars="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    $n = "0";
    for ($i = 0; $i < strlen($btcaddress); $i++) {
        $p1 = strpos($chars, $btcaddress[$i]);
        if ($p1 === false) return false;
        $n = bcmul($n, "58");
        $n = bcadd($n, (string)$p1);
    }
    // Peel off bytes to get checksum / hash / version:
    $checksum = "";
    for ($i = 0; $i < 4; $i++) {
        $byte = bcmod($n, "256");
        $checksum = chr((int)$byte) . $checksum;
        $n = bcdiv($n, "256");
    }
    $hash = "";
    for ($i = 0; $i < 20; $i++) {
        $byte = bcmod($n, "256");
        $hash = chr((int)$byte) . $hash;
        $n = bcdiv($n, "256");
    }
    $version = (int)$n;

    // Make sure checksum is correct:
    $check = hash('sha256', hash('sha256', chr($version).$hash, true), true);
    if (substr($check,0,4) != $checksum) return false;

    return array($version, $hash, $checksum);
}

//
// Convert a Bitcoin address to a raw-bytes Script
//
// Returns false if passed an invalid Bitcoin address,
// otherwise returns an array
// containing (boolean fTestnet, string Script)
//
function address_to_script($btcaddress)
{
    $vhc = decode_base58($btcaddress);
    if ($vhc === False) return False;

    $version = $vhc[0];
    $hash = $vhc[1];

    $testnet = false;
    $script = "";
    switch ($version) {
    case 111:
        $testnet = true; // ... fall through
    case 0:
        // Pay to public key:
        // DUP HASH160 push-0x14-bytes ...hash... EQUALVERIFY CHECKSIG
        $script = "\x76\xa9\x14".$hash."\x88\xac";
        break;
    case 196:
        $testnet = true; // ... fall through
    case 5:
        // Pay to script hash:
        // HASH160 push-0x14-bytes ... hash ... EQUAL
        $script = "\xa9\x14".$hash."\x87";
        break;
    default:
        return false;
    }
    return array($testnet, $script);
}

?>
