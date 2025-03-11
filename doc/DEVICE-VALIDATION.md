# Validating Your Device

pCloud requires "first time" validation for all devices. In the standard use case, where the user is running `pcloudcc` on the same host s/he normally works on, this can be completed by simply logging into pcloud.com using the web browser (and often, it already has been). Non-standard use cases (e.g., running `pcloudcc` on a remote server) require a different approach. 

# Workarounds

Props to [@tieum](https://github.com/tieum), [@ebouda333](https://github.com/ebouda33), [@CorvusCorax](https://github.com/CorvusCorax), and [@tomash](https://github.com/tomash) for suggesting the following workarounds:
 
**Dockerized Carbonyl**. *Requires Docker or Podman on the host.*. Run [carbonyl](https://github.com/fathyb/carbonyl) in a container on the target host to complete the validation.

```
docker run --network host --rm -ti fathyb/carbonyl https://my.pcloud.com
```

**SOCKS proxy over SSH** *Requires TCP port forwarding over SSH*. Log in to the remote host using the command `ssh -D <port>` to enable a SOCKS proxy on `localhost:<port>`. Configure your local web browser to use `localhost:<port>` as its proxy, then log in to pcloud.com and validate the device. *Do not forget to remove the proxy from your browser configuration when done.*
