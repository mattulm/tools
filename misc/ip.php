<?php
//Find the IP of the visitor
     if (getenv("HTTP_CLIENT_IP") && strcasecmp(getenv("HTTP_CLIENT_IP"), "unknown"))
     {
        $rip = getenv("HTTP_CLIENT_IP");
     }
     else if (getenv("HTTP_X_FORWARDED_FOR") && strcasecmp(getenv("HTTP_X_FORWARDED_FOR"), "unknown"))
     {
        $rip = getenv("HTTP_X_FORWARDED_FOR");
     }
     else if (getenv("REMOTE_ADDR") && strcasecmp(getenv("REMOTE_ADDR"), "unknown"))
     {
        $rip = getenv("REMOTE_ADDR");
     }
     else if (isset($_SERVER['REMOTE_ADDR']) && $_SERVER['REMOTE_ADDR'] &&
              strcasecmp($_SERVER['REMOTE_ADDR'], "unknown"))
     {
        $rip = $_SERVER['REMOTE_ADDR'];
     }
     else
     {
        $rip = "unknown";
     }

//Display the IP of the Visitor
echo "Your IP is $rip";
?>
