<!DOCTYPE html>
<html lang="<?php echo $lang; ?>">
  <head>
   <!-- Meta, title, CSS, favicons, etc. -->
    <meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="AlternC, Web and Mail Hosting software control panel.">
<meta name="keywords" content="AlternC Software Linux Debian Gnu Hosting Web Mail">

      <title>AlternC<?php if (isset($title)) { echo " - ".$title; } ?></title>

<!-- Bootstrap core CSS -->

<link rel="stylesheet" href="/assets/bootstrap.min.css">

<link rel="stylesheet" href="/assets/css/docs.min.css">

<!--[if lt IE 9]><script src="/assets/js/ie8-responsive-file-warning.js"></script><![endif]-->
<script src="/assets/js/ie-emulation-modes-warning.js"></script>

<!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
<!--[if lt IE 9]>
  <script src="/assets/html5shiv.min.js"></script>
  <script src="/assets/respond.min.js"></script>
<![endif]-->

<!-- Favicons -->
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="icon" href="/favicon.ico">

  </head>
  <body>


    <!-- Docs page layout -->
    <div class="bs-docs-header" id="content">
      <div class="container">
			 <div style="float: left; padding-right: 30px">
			 <a href="/"><img src="/logo.png" alt="AlternC" /></a>
			 </div>
        <h1><a href="/">AlternC</a></h1>
      <p><?php 
   switch ($lang) {
   case "fr":
   echo "Suite logicielle de gestion de serveur web & mail";
   break;
   case "en":
   default:
   echo "Web and Mail server management software";
   } 
?></p>
<?php if (isset($title)) { echo "<p>".$title."</p>"; } ?>
      </div>
    </div>

    <div class="container bs-docs-container">

      <div class="row">
        <div class="col-md-9" role="main">
          <div class="bs-docs-section">

