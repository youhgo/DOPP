# How to Use

DOPP is really easy to use thanks to the API

## Upload an archive

### With the API
The API Endpoint to send an archive is this one: https://youDOPPAdress/api/parse/parse_archive

The Endpoint is waiting for the archive file and a json parameter

The Json parameter must look like that
```json
{"caseName": "name_of_your_case"}
```

It is possible to configure the tools you want to launch or not using the "config" parameter.
The final JSON must look like that : 
```json
{
  "caseName": "Name_Of_Your_Case" ,
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
  "mpp": 0
 }
}
```

In the "config" parameter, each line represent a tool.
To use a tool, set his value to 1.
By default, all tools are set to 1.

For exemple, send an archive through Curl :
```bash
curl -X POST -k https://DOPP.localhost/api/parse/parse_archive -F file=@"/home/hro/Documents/cyber/working_zone/archive_orc/PC1.7z" -F json='{"caseName":"test"}'
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

```bash 
https://DOPP.localhost/api/check/<string:task_id>
```
```bash 
https://DOPP.localhost/api/debug_log/<string:task_id>
```
```bash 
https://DOPP.localhost/api/running_log/<string:task_id>
```
```bash 
https://DOPP.localhost/api/get_running_tasks
```
```bash 
https://DOPP.localhost/api/stop_analyze_tasks
```
```bash 
https://DOPP.localhost/api/get_running_tasks_parse
```





