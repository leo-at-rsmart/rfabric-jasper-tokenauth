rfabric-jasper-tokenauth
========================

Implements Spring Security classes to permit server-to-server proxy token authentication between rFabric and JasperReports Server

Build Instructions
==================

+ Download JasperReports Server 4.7.0:
http://community.jaspersoft.com/sites/default/files/releases/jasperreports-server-4.7.0-src.zip
+ Unzip JasperReports Server 4.7.0 to a directory (I will refer to it as $JASPER_HOME)
+ Build this project with Maven 3.0 or greater, using the command:
    mvn -Djasperserver-repo=$JASPER_HOME/jasperserver-repo clean install
