#!/bin/bash

mvn clean compile assembly:single
cp target/appseclab-1.0-SNAPSHOT-jar-with-dependencies.jar .
