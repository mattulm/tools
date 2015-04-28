for (( x=1; x<10; x++ )); do
	printf "HEAD / HTTP/1.0\nHost: www.domain.com\n\n" | nc www.domain.com 80 | grep -i last-modified
done