FROM ubuntu:22.04

RUN apt update && apt install -y wget bzip2 libqt5gui5 libcanberra-gtk-module libcanberra-gtk3-module libnss3 libdbus-glib-1-2 openjdk-19-jdk

ENV DISPLAY=$DISPLAY

RUN wget -O burpsuite_community_linux_v2023_7_1.sh 'https://portswigger-cdn.net/burp/releases/download?product=community&version=2023.7.1&type=Linux' &&\
	chmod +x burpsuite_community_linux_v2023_7_1.sh &&\
	(echo -ne '\n'; echo '/opt/BurpSuiteCommunity/'; echo 'n') | ./burpsuite_community_linux_v2023_7_1.sh -c

RUN wget -O geckodriver-v0.33.0-linux64.tar.gz 'https://github.com/mozilla/geckodriver/releases/download/v0.33.0/geckodriver-v0.33.0-linux64.tar.gz' &&\
	tar xvf geckodriver-v0.33.0-linux64.tar.gz &&\
	chmod +x geckodriver &&\
	mv geckodriver /root/

RUN wget -O firefox.tar.bz2 'https://download-installer.cdn.mozilla.net/pub/firefox/releases/115.0.3/linux-x86_64/en-US/firefox-115.0.3.tar.bz2' &&\
	tar xvf firefox.tar.bz2 -C /opt/ &&\
	ln -s /opt/firefox/firefox /usr/bin/firefox

COPY msg_def.json /opt/BurpSuiteCommunity/msg_def.json
