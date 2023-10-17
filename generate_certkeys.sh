#!/bin/bash -ex
ssh-keygen -t rsa -b 4096 -f user_ca -C user_ca -N ""
ssh-keygen -f user-key -b 4096 -t rsa -N ""
ssh-keygen -s user_ca -I test@example.com -n ec2-user,testuser -V +365d user-key.pub
