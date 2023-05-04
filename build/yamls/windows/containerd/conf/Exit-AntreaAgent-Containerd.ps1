$token=cat /var/run/antrea/apiserver/loopback-client-token
curl.exe --insecure --header "Authorization: Bearer $token" https://127.0.0.1:10350/exit
