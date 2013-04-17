<?php
/*
 * fillInFormValues()  : Written by Gavin Andresen (www.skypaint.com/gavin/).
 *    Do with it what you will.
 * Requires PHP version 4.3.0 or later (uses PREG_OFFSET_CAPTURE)
 */

/**
 * Given HTML code for a form, and
 * a $_REQUEST-type array, returns the HTML code modified
 * so the <input>, <textarea>, and <select>/<option> tags
 * reflect the values in the $_REQUEST.
 * Use to repopulate forms that fail input validation.
 * This also checks for form errors in $formErrors, and
 * modifies <label> tags to make them class "error".
 * It also fill in a <ul class="error">...</ul> list with
 *  the $formErrors.
 * NOTE: doesn't work with file upload fields (<input type="file">).
 * ALSO NOTE: Pretty forgiving in the flavors of HTML it takes, but
 *  it does assume the HTML is valid-- it is NOT as forgiving as
 *  some browsers are with invalid markup (e.g. it won't recognize
 *  < input> as a valid tag, it's gotta be <input>, and requires
 *  that <textarea> tags have a matching </textarea>, etc).
 *
 * @param string $formHTML
 * @param array $request
 * @return string Modified version of $formHTML
 */
function fillInFormValues($formHTML, $request = null, $formErrors = null)
{
  if ($request === null) {
    // magic_quotes on: gotta strip slashes:
    if (get_magic_quotes_gpc()) {
      function stripslashes_deep(&$val) {
        $val = is_array($val) ? array_map('stripslashes_deep', $val)
          : stripslashes($val);
       return $val;
      }
      $request = stripslashes_deep($_REQUEST); 
    }
    else {
      $request = $_REQUEST;
    }
  }
  if ($formErrors === null) { $formErrors = array(); }

  $h = new fillInFormHelper($request, $formErrors);
  return $h->fill($formHTML);
}

/**
 * Helper class, exists to encapsulate info needed between regex callbacks.
 */
class fillInFormHelper
{
  var $request;  // Normally $_REQUEST, passed into constructor
  var $formErrors;
  var $idToNameMap; // Map form element ids to names

  function fillInFormHelper($r, $e)
  {
    $this->request = $r;
    $this->formErrors = $e;
  }

  function fill($formHTML)
  {
    $s = fillInFormHelper::getTagPattern('input');
    $formHTML = preg_replace_callback("/$s/is", array(&$this, "fillInInputTag"), $formHTML);

    // Using simpler regex for textarea/select/label, because in practice
    // they never have >'s inside them:
    $formHTML = preg_replace_callback('!(<textarea([^>]*>))(.*?)(</textarea\s*>)!is',
                                      array(&$this, "fillInTextArea"), $formHTML);

    $formHTML = preg_replace_callback('!(<select([^>]*>))(.*?)(</select\s*>)!is',
                                      array(&$this, "fillInSelect"), $formHTML);

    // Form errors:  tag <label> with class="error", and fill in
    // <ul class="error"> with form error messages.
    $errs = $this->formErrors;
    $formHTML = preg_replace_callback('!<label([^>]*)>!is',
                                      array(&$this, "fillInLabel"), $formHTML);
    $this->formErrors = $errs;
    $formHTML = preg_replace_callback('!<ul class="error">.*?</ul>!is',
                                      array(&$this, "getErrorList"), $formHTML);
    
    return $formHTML;
  }

  /**
   * Returns pattern to match given a HTML/XHTML/XML tag.
   * NOTE: Setup so only the whole expression is captured
   * (subpatterns use (?: ...) so they don't catpure).
   * Inspired by http://www.cs.sfu.ca/~cameron/REX.html
   *
   * @param string $tag  E.g. 'input'
   * @return string $pattern
   */
  function getTagPattern($tag)
  {
    $p = '(';  // This is a hairy regex, so build it up bit-by-bit:
    $p .= '(?is-U)'; // Set options: case-insensitive, multiline, greedy
    $p .= "<$tag";  // Match <tag
    $sQ = "(?:'.*?')"; // Attr val: single-quoted...
    $dQ = '(?:".*?")'; // double-quoted...
    $nQ = '(?:\w*)'; // or not quoted at all, but no wacky characters.
    $attrVal = "(?:$sQ|$dQ|$nQ)"; // 'value' or "value" or value
    $attr = "(?:\s*\w*\s*(?:=$attrVal)?)"; // attribute or attribute=
    $p .= "(?:$attr*)"; // any number of attr=val ...
    $p .= '(?:>|(?:\/>))';  // End tag: > or />
    $p .= ')';
    return $p;
  }

  /**
   * Returns value of $attribute, given guts of an HTML tag.
   * Returns false if attribute isn't set.
   * Returns empty string for no-value attributes.
   * 
   * @param string $tag  Guts of HTML tag, with or without the <tag and >.
   * @param string $attribute E.g. "name" or "value" or "width"
   * @return string|false Returns value of attribute (or false)
   */
  function getAttributeVal($tag, $attribute) {
    $matches = array();
    // This regular expression matches attribute="value" or
    // attribute='value' or attribute=value or attribute
    // It's also constructed so $matches[1][...] will be the
    // attribute names, and $matches[2][...] will be the
    // attribute values.
    preg_match_all('/(\w+)((\s*=\s*".*?")|(\s*=\s*\'.*?\')|(\s*=\s*\w+)|())/s',
                   $tag, $matches, PREG_PATTERN_ORDER);

    for ($i = 0; $i < count($matches[1]); $i++) {
      if (strtolower($matches[1][$i]) == strtolower($attribute)) {
        // Gotta trim off whitespace, = and any quotes:
        $result = ltrim($matches[2][$i], " \n\r\t=");
        if (isset($result[0]) && $result[0] == '"') { $result = trim($result, '"'); }
        else { $result = trim($result, "'"); }
        return $result;
      }
    }
    return false;
  }
  /**
   * Returns new guts for HTML tag, with an attribute replaced
   * with a new value.  Pass null for new value to remove the
   * attribute completely.
   * 
   * @param string $tag  Guts of HTML tag.
   * @param string $attribute E.g. "name" or "value" or "width"
   * @param string $newValue
   * @return string
   */
  function replaceAttributeVal($tag, $attribute, $newValue) {
    if ($newValue === null) {
      $pEQv = '';
    }
    else {
      // htmlspecialchars here to avoid potential cross-site-scripting attacks:
      $newValue = htmlspecialchars($newValue);
      $pEQv = $attribute.'="'.$newValue.'"';
    }

    // Same regex as getAttribute, but we wanna capture string offsets
    // so we can splice in the new attribute="value":
    preg_match_all('/(\w+)((\s*=\s*".*?")|(\s*=\s*\'.*?\')|(\s*=\s*\w+)|())/s',
                   $tag, $matches, PREG_PATTERN_ORDER|PREG_OFFSET_CAPTURE);

    for ($i = 0; $i < count($matches[1]); $i++) {
      if (strtolower($matches[1][$i][0]) == strtolower($attribute)) {
        $spliceStart = $matches[0][$i][1];
        $spliceLength = strlen($matches[0][$i][0]);
        $result = substr_replace($tag, $pEQv, $spliceStart, $spliceLength);
        return $result;
      }
    }

    if (empty($pEQv)) { return $tag; }

    // No match: add attribute="newval" to $tag (before closing tag, if any):
    $closed = preg_match('!(.*?)((>|(/>))\s*)$!s', $tag, $matches);
    if ($closed) {
      return $matches[1] . " $pEQv" . $matches[2];
    }
    return "$tag $pEQv";
  }

  /**
   * Finds $tag's name property, returns it and value (if any) in $r
   *
   * @param string $tag  HTML tag with name="..."
   * @param array $r  Gets modified if name uses [] syntax
   * @param boolean $collapse  True to collapse out name[]
   * @return array ($name, $value)  nulls if no name or no value in $r
   */
  function findName($tag, &$r, $collapse) {
    $name = fillInFormHelper::getAttributeVal($tag, "name");
    if (false === $name) { return array(null,null); }
    return array($name, fillInFormHelper::findInRequest($name, $r, $collapse));
  }

  /**
   * Finds $name in $r array, returns value (or null if not found).
   *
   * @param string $name  E.g. "foo" or "foo[]" or "foo[bar][]"
   * @param array $r  Gets modified if $name uses [] syntax
   * @param boolean $collapse  true: remove value if [] syntax
   * @return mixed $value  null if $request[$name] doesn't exist
   */
  function findInRequest($name, &$r, $collapse) {
    preg_match('/^([^\[]*)(\[([^\]]*)\])?(.*?)$/', $name, $matches);
    if (empty($matches) or !array_key_exists($matches[1], $r)) { return null; }
    // $name is something like 'foo':
    if (($matches[2] === '') or !is_array($r[$matches[1]])) { return $r[$matches[1]]; }
    $a =& $r[$matches[1]];
    // $name is something like 'foo[]':
    if ($matches[3] === '') {
      if ($collapse) { return array_shift($a); }
      return $a;
    }
    // $name is something funky like foo[bar] or foo[bar][ick][] : 
    return fillInFormHelper::findInRequest($matches[3].$matches[4], $a, $collapse);
  }

  /**
   * Get id attribute, and add it to the idToNameMap;
   * also converts id's like 'foo[]' to 'foo_0'
   *
   * @param string $tag
   * @param string $name
   */
  function addToNameMap(&$tag, $name)
  {
    $id = fillInFormHelper::getAttributeVal($tag, "id");
    if ($id === false) { return; }
    if (strpos($id, '[]') === false) {
      $this->idToNameMap[$id] = $name;
      return;
    }
    if (!isset($this->idToNameMap[$id])) { $this->idToNameMap[$id] = array(); }
    $n = count($this->idToNameMap[$id]);
    $newID = str_replace('[]', '', $id) . "_$n";
    $newName = str_replace('[]', "[$n]", $name);
    $tag = fillInFormHelper::replaceAttributeVal($tag, "id", $newID);
    $this->idToNameMap[$id][] = array($newID, $newName);
  }

  /**
   * Returns modified <input> tag, based on values in $request.
   * 
   * @param array $matches
   * @return string Returns new guts.
   */
  function fillInInputTag($matches) {
    $tag = $matches[0];

    $type = strtolower(fillInFormHelper::getAttributeVal($tag, "type"));
    if (empty($type)) { $type = "text"; }

    switch ($type) {
      /*
       * Un-comment this out at your own risk (users shouldn't be
       * able to modify hidden fields):
       *    case 'hidden':
       */
    case 'text':
    case 'password':
      list($name, $newValue) = fillInFormHelper::findName($tag, $this->request, true);
      if (false === $name) { return $tag; }
      $this->addToNameMap($tag, $name);
      if (null === $newValue) { return $tag; }
      return fillInFormHelper::replaceAttributeVal($tag, 'value', $newValue);
      break;
    case 'radio':
    case 'checkbox':
      list($name, $newValue) = fillInFormHelper::findName($tag, $this->request, false);
      if (false === $name) { return $tag; }
      $this->addToNameMap($tag, $name);
      $value = fillInFormHelper::getAttributeVal($tag, "value");
      if (false === $value) { $value = "on"; }
      if (null === $newValue) {
        return fillInFormHelper::replaceAttributeVal($tag, 'checked', null);
      }
      $vals = (is_array($newValue)?$newValue:array($newValue));

      if (in_array($value, $vals)) {
        return fillInFormHelper::replaceAttributeVal($tag, 'checked', 'checked');
      }
      return fillInFormHelper::replaceAttributeVal($tag, 'checked', null);
    }
    return $tag;
  }
  /**
   * Returns modified <textarea...> tag, based on values in $request.
   * 
   * @param array $matches
   * @return string Returns new value.
   */
  function fillInTextArea($matches) {
    $tag = $matches[1]; // The <textarea....> tag
    $val = $matches[3]; // Stuff between <textarea> and </textarea>
    $endTag = $matches[4]; // The </textarea> tag

    list($name, $newValue) = fillInFormHelper::findName($tag, $this->request, true);
    if (false === $name) { return $matches[0]; }
    $this->addToNameMap($tag, $name);

    if (null === $newValue) { return $matches[0]; }
    return $tag.htmlspecialchars($newValue).$endTag;
  }
  /**
   * Returns modified <option value="foo"> tag, based on values in $vals.
   * 
   * @param array $matches
   * @return string Returns tag with selected="selected" or not.
   */
  function fillInOption($matches)
  {
    $tag = $matches[1];  // The option tag
    $valueAfter = $matches[2]; // Potential value (stuff after option tag)
    $val = fillInFormHelper::getAttributeVal($tag, "value");
    if (false === $val) { $val = trim($valueAfter); }
    if (in_array($val, $this->selectVals)) {
      return fillInFormHelper::replaceAttributeVal($tag, 'selected', 'selected').$valueAfter;
    }
    else {
      return fillInFormHelper::replaceAttributeVal($tag, 'selected', null).$valueAfter;
    }
  }

  var $selectVals;

  /**
   * Returns modified <select...> tag, based on values in $request.
   * 
   * @param array $matches
   * @return string
   */
  function fillInSelect($matches) {
    $tag = $matches[1];
    $options = $matches[3];
    $endTag = $matches[4];

    $multiple = fillInFormHelper::getAttributeVal($tag, "multiple");
    list($name, $newValue) = fillInFormHelper::findName($tag, $this->request, $multiple===false);
    if (false === $name) { return $matches[0]; }
    $this->addToNameMap($tag, $name);

    if (null === $newValue) { return $matches[0]; }

    $this->selectVals = (is_array($newValue)?$newValue:array($newValue));

    // Handle all the various flavors of:
    // <option value="foo" /> OR <option>foo</option> OR <option>foo
    $s = fillInFormHelper::getTagPattern('option');
    $pat = "!$s(.*?)(?=($|(</option)|(</select)|(<option)))!is";
    $options = preg_replace_callback($pat, array(&$this, "fillInOption"), $options);
    return $tag.$options.$endTag;
  }

  /**
   * Returns modified <label...> tag, based on $formErrors.
   * 
   * @param array $matches
   * @return string
   */
  function fillInLabel($matches) {
    $tag = $matches[0];
    $for = fillInFormHelper::getAttributeVal($tag, "for");
    if ((false === $for) or !isset($this->idToNameMap[$for])) { return $tag; }
    $name =& $this->idToNameMap[$for];
    if (is_array($name)) { // for="foo[]"...  see addToNameMap() above.
      list($newID, $newName) = array_shift($name);
      $tag = fillInFormHelper::replaceAttributeVal($tag, "for", $newID);
    }
    else { $newName = $name; }
    $err = fillInFormHelper::findInRequest($newName, $this->formErrors, false);
    if ($err) {
      return fillInFormHelper::replaceAttributeVal($tag, 'class', 'error');
    }
    return $tag; // No error.
  }

  function messages($a)
  {
    $result = array();
    foreach ($a AS $msg) {
      if (empty($msg)) { continue; }
      if (is_array($msg)) {
        $result = array_merge($result, fillInFormHelper::messages($msg));
      }
      else {
        $result[] = $msg;
      }
    }
    return $result;
  }

  /**
   * Returns modified <ul class="error"> list with $formErrors error messages.
   * 
   * @return string
   */
  function getErrorList() {
    $messages = fillInFormHelper::messages($this->formErrors);
    $result = "";
    foreach (array_unique($messages) AS $m) {
      $result .= " <li>".htmlentities($m)."</li>\n";
    }
    if (empty($result)) { return ""; }  // No errors: return empty string.
    return '<ul class="error">'.$result.'</ul>';
  }
} // End of helper class.

?>
