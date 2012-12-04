rfabric-jasper-tokenauth
========================

Implements Spring Security classes to permit server-to-server proxy token authentication between rFabric and JasperReports Server

Build Instructions
==================

# Download and Install JasperReports Server 4.7.0:
http://community.jaspersoft.com/project/jasperreports-server/releases
# Edit src/main/deployfiles/applicationContext.xml to set the secret key in the authTokenAuthenticationProvider bean (this MUST match the key used in rFabric)
# Build this project with Maven 3.0 or greater, using the command:
    mvn clean install
# Deploy the configuration files to Jasper Reports Server:
    (on a Mac): cp src/main/deployfiles/* /Applications/jasperreports-server-cp-4.7.0/apache-tomcat/webapps/jasperserver/WEB-INF
# Deploy the jar file to Jasper Reports Server:
    (on a Mac): cp target/*.jar /Applications/jasperreports-server-cp-4.7.0/apache-tomcat/webapps/jasperserver/WEB-INF/lib
# Start (or restart) the Jasper Reports Server
