# DO NOT EDIT - See: https://www.eclipse.org/jetty/documentation/current/startup-modules.html

[description]
Download and deploy the Test Spec webapp demo.

[environment]
ee10

[tags]
demo
webapp

[depends]
deploy
jdbc
ee10-jsp
ee10-annotations
ext
ee10-demo-realm
demo-ee10-mock-resources

[files]
basehome:modules/demo.d/demo-ee10-spec.xml|webapps-ee10/demo-ee10-spec.xml
maven://org.eclipse.jetty.ee10.demos/demo-ee10-spec-webapp/${jetty.version}/war|webapps-ee10/demo-ee10-spec.war