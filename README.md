# passport-cert-parser

Parse the e-passport CA certificate list

### How to Work

- Download `icaopkd-001-dsccrl-xxx.ldif` and `icaopkd-002-ml-xxx.ldif` from [ICAO](https://download.pkd.icao.int/download)

- Put the files to `/docs/ldif`

- Edit `MASTER_LIST_FILE_NAME` and `CRL_FILE_NAME` of [Config](https://github.com/duanyytop/passport-cert-parser/blob/main/src/main/java/dev/gw/Config.java) with the files' name

- Run the below command

```
./gradlew run   // gradle run
```