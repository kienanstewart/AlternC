</div>
       </div>
        
        <div class="col-md-3">
          <div class="bs-docs-sidebar hidden-print hidden-xs hidden-sm" role="complementary">
            <ul class="nav bs-docs-sidenav">
           <?php echo $index; ?>
            </ul>
            <a class="back-to-top" href="#top">
              Back to top
            </a>
    <?php foreach($otherlang as $l=>$name) { ?>
<a class="back-to-top" href="<?php echo $uri."-".$l; ?>">
   <?php echo $name; ?>
            </a>
   <?php } ?>

          </div>
        </div>
        
      </div>
    </div>

    <!-- Footer
================================================== -->
<footer class="bs-docs-footer" role="contentinfo">
  <div class="container">
    <div class="bs-docs-social">
  <ul class="bs-docs-social-buttons">
    <li class="follow-btn">
      <a href="/" class="twitter-follow-button">AlternC</a>
    </li>
    <li class="follow-btn">
      <a href="http://demo.alternc.org" class="twitter-follow-button"><?php
switch ($lang) {
case "fr":
 echo "Serveur de Démonstration";
break;
case "en":
default:
 echo "Demonstration Server";
break;
}
?></a>
    </li>
    <li class="follow-btn">
      <a href="https://twitter.com/AlternC_en" class="twitter-follow-button"><?php
switch ($lang) {
case "fr":
 echo "@AlternC_en sur Twitter";
break;
case "en":
default:
 echo "@AlternC_en on Twitter";
break;
}
?></a>
    </li>
    <li class="follow-btn">
    <a href="https://github.com/alternc/" class="twitter-follow-button"><?php
switch ($lang) {
case "fr":
 echo "Code source sur Github";
break;
case "en":
default:
 echo "Source code on Github";
break;
}
?></a>
    </li>
  </ul>
</div>
</div>

</footer>

<!-- Bootstrap core JavaScript
================================================== -->
<!-- Placed at the end of the document so the pages load faster -->
<script src="/assets/jquery.min.js"></script>

  <script src="/bootstrap.min.js"></script>
  <script src="/assets/js/docs.min.js"></script>

<!-- IE10 viewport hack for Surface/desktop Windows 8 bug -->
<script src="/assets/js/ie10-viewport-bug-workaround.js"></script>


  </body>
</html>
