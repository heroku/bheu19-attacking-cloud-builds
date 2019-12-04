# Checking for forgotten ARG build variables

* Adjust [app/build.sh](app/build.sh) to send `printenv` output to your own HTTP endpoint.
* Adjust envvars.txt as needed.
* Create Dockerfile and push to buildsystem:
```
bash gen_dockerfile.sh envvars.txt > Dockerfile
```

