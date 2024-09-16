# How to install

## REQUIREMENT
You will need the following requirements :
- Docker -> [Install link](https://docs.docker.com/engine/install/ubuntu/)
- Docker-compose ->  [Install link](https://phoenixnap.com/kb/install-docker-compose-on-ubuntu-20-04)

## Installation

First download the repo :
```bash
git clone https://github.com/Xbloro/DOPP
cd DOPP
```

### Docker Set UP
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

## Build
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

## Launch

To launch DOPP:
```bash
docker-compose up 
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