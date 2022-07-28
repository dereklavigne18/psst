# psst
Psst is a simple secret keeper, which allows you to store your secrets locally and access them using a password at will. Currently, only cli interactions are supported.

## Quickstart

1. `Install Docker` 

    For now, psst only requires Docker and Docker Compose to run, so you'll need to have those running for it to work.

2. `Add Psst to your path`

    While you can run the psst file from anywhere, it is recommended to add `psst/bin` to your path. All further instructions will assume you've done so.

3. `Start generating secrets!`

    You can now use help dialogues to navigate your available options and start storing and viewing secrets. See below for examples.
    
   ```commandline
    psst --help
    ```
   
## Examples

Each secret has its own password, you can use the below command to store a secret behind a password of your choosing.

```commandline
psst register --secret <secret name> --value <secret itself> --password <protecting password>
```

To view the secret you must provide the correct password for the secret. You can use the below command to view.

```commandline
psst ask --secret <secret name> --password <protecting password>
```
 
