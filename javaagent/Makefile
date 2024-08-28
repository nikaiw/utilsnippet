# Variables
JAVAC = javac
JAR = jar
JAVA_SRC = StaticMethodListerAgent.java
CLASS_FILES = StaticMethodListerAgent.class
JAR_NAME = StaticMethodListerAgent.jar
MANIFEST_FILE = MANIFEST.MF
CLASSGRAPH_JAR = classgraph-4.8.154.jar

# Default target
all: $(JAR_NAME)

# Compile the Java source files
%.class: %.java
	$(JAVAC) -cp $(CLASSGRAPH_JAR) $<

# Create the JAR file
$(JAR_NAME): $(CLASS_FILES) $(MANIFEST_FILE)
	$(JAR) cmf $(MANIFEST_FILE) $(JAR_NAME) $(CLASS_FILES)

# Clean up generated files
clean:
	rm -f $(CLASS_FILES) $(JAR_NAME)

# Manifest file creation
$(MANIFEST_FILE):
	echo "Premain-Class: StaticMethodListerAgent" > $(MANIFEST_FILE)

# Phony targets
.PHONY: all clean

