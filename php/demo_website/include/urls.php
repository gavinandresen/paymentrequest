<?php
/**
 * Useful URL functions.
 * @package common
 */

/**
 *  Returns a string with the protocol and server part of the current URL.
 * 
 *
 * @return string E.g. https://www.foo.com:8443
 */
function HttpServer()
{
  $port = $_SERVER['SERVER_PORT'];
  if (isset($_SERVER['HTTPS']) &&
      $_SERVER["HTTPS"] == "on") {
    $result = "https://";
    $result .= $_SERVER['SERVER_NAME'];
    if ($port != 443) { // 443 is default https
      $result .= ":" . $port;
    }
  }
  else {
  	$result = "http://";
    $result .= $_SERVER['SERVER_NAME'];
    if ($port != 80) { // 80 is default http
      $result .= ":" . $port;
    }
  }
  return $result;
}

/**
 *  Turns a relative URL into an http-1.1-compliant absolute URL.
 *
 * @param string $url  E.g. /foo/bar
 * @return string  E.g http://my.server.com/foo/bar
 */
function AbsoluteURL($url)
{
  $absoluteURL = "";
  if (preg_match('_^\w+://_', $url)) {
	$absoluteURL = $url;
  }
  else if (isset($url[0]) && $url[0] == '/') {
    $absoluteURL = HttpServer() . $url;
  }
  else {
    $dir = dirname($_SERVER['PHP_SELF']);
    $dir = strtr($dir, '\\', '/'); // Deal with Windows nonsense...
	if ($dir[strlen($dir)-1] != '/') { $dir .= '/'; }
    $absoluteURL = HttpServer() . $dir . $url;
  }
  return $absoluteURL;
}

/**
 * Remove a list of arguments from the ?foo=bar... part of a URL
 *
 * @param string $url  E.g. http://www.foo.com/?task=help&user=Fred
 * @param array $args  E.g. array('task')
 * @return string      E.g. http://www.foo.com/?user=Fred
 */
function RemoveArgsFromURL($url, $args)
{
  if ($args === null) { return $url; }
  foreach ($args as $var => $val) {
    $v = urlencode($var);
    // Nuke "&arg=blah" or "?arg=blah" or "&arg=" or "?arg="
    $url = preg_replace("/(&|\?)$v=[^&]*/", '$1', $url);
    // Nuke "&arg&..." or "?arg"&...:
    $url = preg_replace("/(&|\?)$v&/", '$1&', $url);
  }
  return MakeURLPretty($url);
}

/**
 * Add a list of arguments&values to a URL
 *
 * @param string $url  E.g. http://www.foo.com/?user=Fred
 * @param array $args  E.g. array('task' => 'shop', 'store' => 'Big Y')
 * @return string      E.g. http://www.foo.com/?user=Fred&task=shop&store=Big%20Y
 */
function AddArgsToURL($url, $args)
{
  if ($args === null) { return $url; }
  // This works as a replace, so replace any identically named args in URL:
  $url = RemoveArgsFromURL($url, $args);

  // Doesn't work properly with "fragment" part of URL,
  // so, for now, just don't pass in those!
  assert('strstr($url, "#") === false');

  if (strstr($url, '?') === false) {
    $paramSep = '?';
  }
  else {
    $paramSep = '&';
  }
  foreach ($args as $var => $val) {
    $url .= $paramSep . urlencode($var) . "=" . urlencode($val);
    $paramSep = '&';
  }
  return $url;
}

/**
 *  Cleans up a messy URL into something nice and clean
 *
 * @param string $url  E.g. http://www.foo.com/folder/index.php?
 * @return string      E.g. http://www.foo.com/folder/
 */
function MakeURLPretty($url)
{
  // Make the URL look pretty before doing the redirect:
  $url = preg_replace('/\/index.php/', '/', $url);
  $url = preg_replace('/&&/', '&', $url);
  $url = preg_replace('/\?&/', '?', $url);
  $url = preg_replace('/&$/', '', $url);
  $url = preg_replace('/\?$/', '', $url);

  return $url;
}

/**
 *  Does an http-1.1-compliant redirection to an absolute or relative url.
 *
 * @param string $url
 * @return void        Calls exit to end PHP processing.
 */
function Redirect($url)
{
  $absoluteURL = MakeURLPretty(AbsoluteURL($url));

  if (headers_sent()) {
    // Right, can't just spit out a Location: header, last-ditch effort:
    // Spit out JavaScript code to do a redirect...
    //    echo "<SCRIPT>location.href=\"$absoluteURL\"</SCRIPT>";
    echo "<br>Would like to Redirect to: ";
    echo '<a href="'. $absoluteURL . '">';
    echo $absoluteURL;
    echo "</a>";
  }
  else {
    header("Location: $absoluteURL");
  }
  exit;	
}

/**
 * Send headers to disable browser page caching
 *
 * @return void   Just sends HTTP headers (or adds <META tags if headers sent).
 */
function DoNotCache()
{
  if (headers_sent()) {
    print <<< NO_HEADERS
<META HTTP-EQUIV="Pragma" CONTENT="no-cache">
<META HTTP-EQUIV="Expires" CONTENT="-1">
NO_HEADERS;
  }
  else {
    // From the PHP documentation (function.header.html):
    $now = gmdate("D, d M Y H:i:s");
    header("Expires: $now GMT");
    header("Last-Modified: $now GMT");
    header("Cache-Control: no-store, no-cache, must-revalidate");
    header("Cache-Control: post-check=0, pre-check=0", false);
    header("Pragma: no-cache");
  }
}

/**
 *  Returns true if running on a non-production server.
 *
 * @return boolean
 */
function IsTestServer()
{
  // Little bit of a hack here: assume local IP addresses are test servers...
  if (strpos($_SERVER["SERVER_ADDR"], "127.0.") === 0 ||
      strpos($_SERVER["SERVER_ADDR"], "192.168.") === 0) {
    return true;
  }
  return false;
}

/**
 *  Returns value of key in array, or default_value if key isn't set.
 *
 * @param array $array
 * @param string $key
 * @param mixed $default_value
 * @return mixed
 */
function ArrayGetDefault(&$array, $key, $default_value)
{
  if (is_array($array)&& isset($array[$key])) { return $array[$key]; }
  return $default_value;
}

/**
 * Create anchor tags (links)
 *
 * @param string $text
 * @param string $url
 * @param array $params
 * @return string
 */
function MakeAnchor($text, $url, $params=null)
{
  $result = '<a href="' . AddArgsToURL($url, $params);
  $result .= '">';
  $result .= $text;
  $result .= "</a>";
  return $result;
}

/**
 * Return relative path from one file or directory to another.
 *
 * Notes:
 *  - If you pass in directories, they MUST end in '/'
 *  - Both paths must start at the same place in the filesystem/web server root.
 *  - Don't pass in absolute urls
 * 
 * @param string $path1  E.g. "sub/dir/ectory/index.php"
 * @param string $path2  E.g. "somewhere/else/"
 * @return string        E.g. "../../../somewhere/else/"
 */
function GetRelativePath($path1, $path2)
{
  assert(strpos($path1, "http") !== 0);
  assert(strpos($path2, "http") !== 0);
  $path1 = ltrim($path1, '/');  // Remove leading slashes
  $path2 = ltrim($path2, '/');

  // Get directory and filename bits:
  $dirs1 = explode('/', $path1);
  $file1 = array_pop($dirs1);
  $n = count($dirs1);
  for ($i = 0; $i < $n; $i++) {
    if (empty($dirs1[$i]) || ($dirs1[$i] == ".")) { unset($dirs1[$i]); }
  }
  $dirs1 = array_values($dirs1);
  $dirs2 = explode('/', $path2);
  $file2 = array_pop($dirs2);
  $n = count($dirs2);
  for ($i = 0; $i < $n; $i++) {
    if (empty($dirs2[$i]) || ($dirs2[$i] == ".")) { unset($dirs2[$i]); }
  }
  $dirs2 = array_values($dirs2);

  // Remove common ancestors:
  while ((count($dirs1) > 0) && (count($dirs2) > 0) && ($dirs1[0] == $dirs2[0])) {
    array_shift($dirs1);
    array_shift($dirs2);
  }

  $result = "";
  if (!empty($dirs1)) {
    $result .= str_repeat("../", count($dirs1)); // Go up to common ancestor...
  }
  if (!empty($dirs2)) { // .. then down path2
    $result .= implode("/", $dirs2);
  }
  if (!empty($file2)) { // ... and add filename.
    if (!empty($result)) { $result .= "/"; }
    $result .= $file2;
  }

  return $result;
}

?>
