# How to Use DOPP

DOPP is really easy to use thanks to the API

## DOPP API

### Parsing URL
The API Endpoint to send an archive is this one: https://youDOPPAdress/api/parse/parse_archive

The Endpoint is waiting for the archive file and a json parameter

The Json parameter must look like that
```json
{"caseName": "name_of_your_case", "machineName": "Name_of_the_machine_analyzed"}
```

It is possible to configure the tools you want to launch or not using the "config" parameter.
The final JSON must look like that : 
```json
{
  "caseName": "Name_Of_Your_Case" ,
  "machineName": "Name_of_the_machine_analyzed",
  "config":{
  "EvtxToJson": 1,
  "ParseEvtx": 1,
  "ParseAutoruns": 1,
  "ParseNetwork": 1,
  "ParsePrefetch" : 1,
  "ParseSrum" : 1,
  "ParseSystemHivesRr": 1,
  "parseUserHivesRr": 1,
  "parseSystemHivesRegipy" : 1,
  "parseLnk": 1,
  "parseMft" : 1,
  "plaso" : 1,
  "mpp": 1
 }
}
```

In the "config" parameter, each line represent a tool.
To use a tool, set his value to 1.
By default, all tools are set to 1.

For exemple, send an archive through Curl :
```bash
curl -X POST -k https://DOPP.localhost/api/parse/parse_archive -F file=@"/home/hro/Documents/cyber/working_zone/archive_orc/PC1.7z" -F json='{"caseName":"test", "machineName":"DesktopForest"}'
{
  "debugLogUrl":"https://DOPP.localhost/api/debug_log/b16b2be6-0c04-4540-96e9-ab922c27b2f7",
  "message":"your parsing request has been send to queue",
  "runLogUrl":"https://DOPP.localhost/api/running_log/b16b2be6-0c04-4540-96e9-ab922c27b2f7",
  "statusUrl":"https://DOPP.localhost/api/check/b16b2be6-0c04-4540-96e9-ab922c27b2f7",
  "taskId":"b16b2be6-0c04-4540-96e9-ab922c27b2f7"
  }
```

The response will give you 3 URL and an id:
* debugLogURL will display the debug log of the tool (for developers);
* runLogUrl will display the run log of the tool (for user to know the processing timeline);
* StatusUrl will display if whether or not the task is finished;
* taskID is the ID of your task.

### check URL
This endpoint allows you to check if a task is still running or not, you must provide the ask id provided when using the parsing url
```bash 
https://DOPP.localhost/api/check/<string:task_id>
```

### debug log URL
This endpoint allows you to check the debuglogs of the task
```bash 
https://DOPP.localhost/api/debug_log/<string:task_id>
```

### run log URL
This endpoint allows you to check the run logs of the task
```bash 
https://DOPP.localhost/api/running_log/<string:task_id>
```

### running task url
This endpoint return all running task's ids 
```bash 
https://DOPP.localhost/api/get_running_tasks
```

### stop task url
This endpoint allow you to stop a task by providing it's id
```bash 
https://DOPP.localhost/api/stop_analyze_tasks
```






