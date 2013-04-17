<?php
//
// Simple form validation function.
//

function validateForm($values, $validationData)
{
  $result = array();
  foreach ($validationData AS $name => $valArray) {
    if ((array_search('isRequired', $valArray) !== FALSE) &&
        (!isset($values[$name]) or empty($values[$name]))) {
      $result[$name] = "Please fill in all required fields.";
      continue;
    }
    if (!isset($values[$name]) or empty($values[$name])) continue;

    if (!isset($valArray['type'])) continue;
    switch ($valArray['type']) {
    case 'email':
      if (! preg_match('/^[_a-z0-9-]+(\.[_a-z0-9-]*)*@[a-z0-9-]+(\.[a-z0-9-]+)+$/',$values[$name])) {
        $result[$name] = "Invalid email address ".htmlentities($values[$name]);
      }      
      break;
    case 'btcaddress':
      // pattern-match sanity check:
      if (! preg_match('/^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{27,34}$/',$values[$name])) {
        $result[$name] = "Invalid bitcoin address ".htmlentities($values[$name]);
      }      
      break;
    case 'btcamount':
      if (floatval($values[$name]) <= 0.0 || floatval($values[$name]) >= 21e6) {
        $result[$name] = "Invalid amount ".htmlentities($values[$name]);
      }      
      break;
    }
  }
  return $result;
}

?>
