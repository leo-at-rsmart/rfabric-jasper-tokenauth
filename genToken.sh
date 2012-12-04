#!/bin/sh

CP=~/.m2/repository/commons-codec/commons-codec/1.7/commons-codec-1.7.jar:~/.m2/repository/commons-logging/commons-logging-api/1.1/commons-logging-api-1.1.jar:~/.m2/repository/commons-logging/commons-logging/1.1.1/commons-logging-1.1.1.jar:target/classes

java -classpath $CP com.rsmart.rfabric.jasperreports.auth.AuthTokenGenerator $1 $2
