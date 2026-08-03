MIG-T headless

PER FARLO PARTIRE:

sul terminale:
dentro cartella mig-t-headless-demo lanciare comando:  
javac -cp libs/mig-t-beta-jar-with-dependencies.jar -d out src/main/java/demo/App.java

e dopo:

java -cp "out:libs/mig-t-beta-jar-with-dependencies.jar" migt.App testdata

DA SAPERE:

il wrapper App.java si trova in src/main/java/demo

se re-buildate il jar dovete in seguito copiarlo in /libs

in testdata:

si trovano i msg_def.json, openidferation, e una cartella tests, all'interno di tests ci sono i file json con i test da eseguire

WRAPPER:

metodo buildEntityConfigurationMessage --> simula le chiamate http

riga 55 >> boolean passed = test.execute(capturedMessages, messageTypes); --> dove vengono eseguiti effettivamente i test
