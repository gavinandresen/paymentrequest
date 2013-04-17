<?php
/*
 * Some routines for dealing with certificates
 * All assume you have support for openssl compiled into
 * php.
 */

/*
 * Return true if $certificate is a root cert.
 * $certificate must be a parsed array, not raw unparsed data.
 */
function is_root_certificate($certificate)
{
    return $certificate['issuer'] == $certificate['subject'];
}

/*
 * Given a parsed leaf certificate, fetch its parent
 * and return its (unparsed) data.
 */
function fetch_certificate_parent($leafCertificate)
{
    $pattern = '/CA Issuers - URI:(\\S*)/';
    $matches = array();
    $nMatches = preg_match_all($pattern, $leafCertificate['extensions']['authorityInfoAccess'], $matches);
    if ($nMatches == 0) return false;
    foreach ($matches[1] as $url) {
        $parentCert = file_get_contents($url);
        if ($parentCert && parse_certificate($parentCert)) return $parentCert;
    }
    return false;
}

/*
 * Either parse a PEM certificate, or convert DER to PEM and then
 * parse.
 */
function parse_certificate($certData)
{
    $begin = "-----BEGIN CERTIFICATE-----";
    $end = "-----END CERTIFICATE-----";

    if (strpos($certData, $begin) !== false) {
        return openssl_x509_parse($certData);
    }
    $d = $begin."\n";
    $d .= chunk_split(base64_encode($certData));
    $d .= $end."\n";
    return openssl_x509_parse($d);
}

function pem2der($pem_data) {
   $begin = "CERTIFICATE-----";
   $end   = "-----END";
   if (strpos($pem_data, $begin) === false) return $pem_data;
   $pem_data = substr($pem_data, strpos($pem_data, $begin)+strlen($begin));    
   $pem_data = substr($pem_data, 0, strpos($pem_data, $end));
   $der = base64_decode($pem_data);
   return $der;
}

/*
 * Fetch a whole certificate chain, starting with
 * a leaf certificate. Returns raw certificate data
 * in an array, leaf certificate first.
 */
function fetch_chain($leaf)
{
    $result = array();

    $cert = parse_certificate($leaf);
    if ($cert === false) return false;
    $certData = pem2der($leaf);

    while ($cert !== false && !is_root_certificate($cert))
    {
        $result[] = $certData;
        $certData = fetch_certificate_parent($cert);
        $cert = parse_certificate($certData);
    }

    return $result;
}

?>
