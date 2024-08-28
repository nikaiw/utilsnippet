# Java Agent Static Lister

A Java agent that lists all static methods in the classpath during a Java program's execution.

## Usage

### 1. Build the jar

Use the makefile or run the following:

```bash
javac StaticMethodListerAgent.java
jar cmf MANIFEST.MF StaticMethodListerAgent.jar StaticMethodListerAgent.class
```
### 2. Running the Agent with Your Java Application

To run your Java application with the `StaticMethodListerAgent`, use the `-javaagent` option:

```bash
java -javaagent:/path/to/StaticMethodListerAgent.jar -cp /path/to/yourapp.jar com.yourcompany.MainClass
```

# Example output

![image](https://github.com/user-attachments/assets/e156cfa7-fe7c-4261-8616-2d7d2eb8c280)

