#!/usr/bin/env bash 
ESC_SEQ="\x1b["
COL_RESET=$ESC_SEQ"39;49;00m"
COL_RED=$ESC_SEQ"31;01m"
COL_GREEN=$ESC_SEQ"32;01m"
COL_YELLOW=$ESC_SEQ"33;01m"
COL_BLUE=$ESC_SEQ"34;01m"
COL_MAGENTA=$ESC_SEQ"35;01m"
COL_CYAN=$ESC_SEQ"36;01m"

echo -e "
$COL_RED Please enter website without http for testing header against securityheaders.com $COL_RESET
"

read choice

echo -e "
$COL_GREEN Header is being testing now , please wait.. $COL_RESET
"
curl --silent --request POST 'https://securityheaders.com' -A 'Mozilla/5.0 (X11; Linux i686; rv:25.0) Gecko/20100101 Firefox/25.0' -c ps.txt -d "user_input=http%3A%2F%2Fwww.$choice" "https://securityheaders.com/test-http-headers.php"  > temp1.html

sed '1,294d' temp1.html > temp2.html

cat temp2.html | grep "<td>" > temp3.html
rm temp1.html
rm temp2.html

sed -e 's!http\(s\)\{0,1\}://[^[:space:]]*!!g' -e 's/[@#\$%^&*()=039"]//g' -e 's/<td>//g' -e 's/<img src//g' -e 's/<\/td>//g' -e 's/<p>//g' -e 's/<\/p>//g' -e 's/<b>//g'  -e 's/<\/b>//g' temp3.html > temp4.html

rm temp3.html

sed "s/;/\'/g" temp4.html > temp5
rm temp4.html
sed '$d' temp5 >temp6
rm temp5
sed "s/news/\Good news/g" temp6
rm temp6

