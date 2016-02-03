<?php

// List here the supported languages :
$otherlang=array( 
		 "fr" => "Français",
		 "en" => "English",
		  );
$locales=array("fr" => "fr_FR.UTF-8",
	       "en" => "en_GB.UTF-8",
	       );

$uri=trim($_SERVER["REQUEST_URI"],"/");

$lang="en";
if (isset($_SERVER["HTTP_ACCEPT_LANGUAGE"])) {
    $l=substr($_SERVER["HTTP_ACCEPT_LANGUAGE"],0,2);
    if (isset($otherlang[$l])) {
        $lang=$l;
    }
}

// auto lang redirect:
if (!$uri) {
  header("Location: /Home-".$lang."");
  exit();
}

if (preg_match('#^(.*)-([^-]*)$#',$uri,$mat)) {
  $lang=$mat[2]; 
  $uri=$mat[1];
} else {
    header("Location: /".$uri."-".$lang);
    exit();
}

if (!isset($otherlang[$lang])) {
  header("HTTP/1.0 404 Not Found");
  echo "<h1>Lang not supported</h1>";
  exit();
}

// set locales:
putenv("LC_MESSAGES=".$locales[$lang]);
putenv("LANG=".$locales[$lang]);
putenv("LANGUAGE=".$locales[$lang]);
// this locale MUST be selected in "dpkg-reconfigure locales"
setlocale(LC_ALL,$locales[$lang]); 

unset($otherlang[$lang]);

header("Content-Type: text/html; charset=UTF-8");

if (!file_exists("../pages/".$uri."-".$lang.".md")) {
    if (file_exists("../pages/".ucfirst($uri)."-".$lang.".md")) {
        header("Location: /".ucfirst($uri)."-".$lang);
        exit();
    }
    header("HTTP/1.0 404 Not Found");
    echo "<h1>File not found</h1>";
    exit();
}

// automatic compilation / caching of HTML pages
if (!file_exists("../pages/".$uri."-".$lang.".html") ||
    filemtime("../pages/".$uri."-".$lang.".html") < filemtime("../pages/".$uri."-".$lang.".md") ) {
  passthru("github-markup ".escapeshellarg("../pages/".$uri."-".$lang.".md")." >".escapeshellarg("../pages/".$uri."-".$lang.".html")." 2>&1");
}

$f=fopen("../pages/".$uri."-".$lang.".html","rb");

$headings=array();
$cur=array(); $id=""; $name="";
$first=true;
while ($s=fgets($f,1024)) {
  if (preg_match('#<h1 id="([^"]*)">([^<]*)</h1>#',$s,$mat)) {
    if ($first) { $title=$mat[2]; $first=false; }
    if ($id) $headings[]=array("id"=>$id, "name"=>$name, "cur"=>$cur);
    $id=$mat[1]; $name=$mat[2];
    $cur=array();
  }
  if (preg_match('#<h2 id="([^"]*)">([^<]*)</h2>#',$s,$mat)) {
    $cur[]=array("id"=>$mat[1], "name"=>$mat[2]);
  }
}
if ($id) $headings[]=array("id"=>$id, "name"=>$name, "cur"=>$cur);

ob_start();
foreach($headings as $v) {
?>                
  <li>
    <a href="#<?php echo $v["id"]; ?>"><?php echo $v["name"]; ?></a>
<?php if (count($v["cur"])) { ?>
  <ul class="nav">
    <?php foreach($v["cur"] as $vv) { ?>
    <li><a href="#<?php echo $vv["id"]; ?>"><?php echo $vv["name"]; ?></a></li>
    <?php } ?>
  </ul>
  <?php } ?>
</li>
<?php
}
    $index=ob_get_clean();

// SPIT OUT THE PAGE:

require_once("head.php");

readfile("../pages/".$uri."-".$lang.".html");

require_once("foot.php");

