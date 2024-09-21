# Dfir ORC Parser Project - Install

Usefull links:
* DOPP is available [here](https://github.com/youhgo/DOPP)
* How to install DOPP, tutorial [here](https://youhgo.github.io/DOPP-how-to-install-EN/)
* How to use DOPP, tutorial [here](https://youhgo.github.io/DOPP-how-to-use-EN/)
* DOPP result architecture, explained [here](https://youhgo.github.io/DOPP-Results/)

## Prerequisite

You need to install Docker and docker-compose :

To install Docker you can go [here](https://docs.docker.com/engine/install/)

or
```bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

To install Docker-compose you can go [here](https://docs.docker.com/compose/install/linux/#install-using-the-repository)

or

```bash
sudo apt-get update
sudo apt-get install docker-compose-plugin
```

Download DOPP :

```bash
git clone https://github.com/youhgo/DOPP
```


## Set UP Docker and Docker-compose

To be able to share the results with the analyst, we create a shared volume between the machine and docker.
You need to update the path of the volume to where ever you want.

Edit the file : docker-compose.yml and change the "volumes" variable in the section "doppApi" and "doppWorker". Do not edit other "volumes" variable. 

Please do not change after the ":"

For example :
```yml
    volumes:
      - /please/change/me/shared:/python-docker/shared_files/
```
Will become :
```yml
    volumes:
      - /home/hro/Documents/working_zone/shared:/python-docker/shared_files/
```

That's mean that on my machine, i will be able to access all the file in the directory :
```bash
/home/hro/Documents/working_zone/shared/
```

## Build and Run
You should be able to build Everything in the DOPP directory :
```bash
docker-compose up --build
```

The tool should be up and running. You should get :
```bash
curl -X GET -k https://dopp.localhost/ | jq

{
  "message": "Welcom to Dfir-Orc Parser Project",
  "serveurTime": "02/05/2024 02:06:33",
  "status": "OK"
}
```

DOPP is now ready to go !

To learn How to use DOPP, tutorial is [here](https://youhgo.github.io/DOPP-how-to-use-EN/)
