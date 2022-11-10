# securityAssignmentMain

# 개요

서버 분석 프로그램을 제작하기 위해 **“Python”** 언어를 사용했으며 IDE는 **“Pycharm”**을 사용했습니다. 프로그램을 사용하기 위해서는 실행을 시킨 후 서버의 IP를 입력하면 됩니다. 이 후 *“Please wait until the process is finished…”* 문구가 뜨며 1분 내외의 시간을 기다리면  *“Process Finished. IP “IP주소” has following information”*문구가 뜨며 서버 정보를 정리해서 출력합니다. 

# 1번. IP -----

![스크린샷 2022-11-11 오전 1.36.42.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/eae1985f-af42-410f-8818-bc49236b85af/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2022-11-11_%E1%84%8B%E1%85%A9%E1%84%8C%E1%85%A5%E1%86%AB_1.36.42.png)

![스크린샷 2022-11-11 오전 1.43.26.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/e8234971-e5d6-43f1-be7c-83732e8f76da/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2022-11-11_%E1%84%8B%E1%85%A9%E1%84%8C%E1%85%A5%E1%86%AB_1.43.26.png)

총 5가지의 포트가 있으며 21, 8080은 closed, 22,80,3306은 open상태인 것을 알 수 있다. 간략한 포맷으로 정리해본 정보들과 딕셔너리로 출력되는 더 많은 정보를 확인하면 아래와 같은 정보를 얻을 수 있다.

- 파일 전송: ftp로 추정하나 닫혀있음
- SSH: 22포트에 열려있음. OpenSSH 8.9p1 Ubuntu 3
- 웹서버: 80번 포트에 http apache 운영중 버전은 2.4.52
- 데이터베이스: 3306포트 열려있음. mysql 8.0.31
- 웹-서버 중개인: 8080포트 http-proxy로 추정하나 닫혀있음
- 운영체제: 95% 확률로 리눅스 5.1

# 2번. IP -----

![스크린샷 2022-11-11 오전 1.42.56.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/1e8860a8-fa7c-453a-84b1-b72cc4a6cea0/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2022-11-11_%E1%84%8B%E1%85%A9%E1%84%8C%E1%85%A5%E1%86%AB_1.42.56.png)

![스크린샷 2022-11-11 오전 1.42.20.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/38ecd320-1806-4003-8886-1235df2b4c03/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2022-11-11_%E1%84%8B%E1%85%A9%E1%84%8C%E1%85%A5%E1%86%AB_1.42.20.png)

총 5가지의 포트가 있으며 3306, 8080은 closed, 21, 22, 80은 open상태인 것을 알 수 있다. 간략한 포맷으로 정리해본 정보들과 딕셔너리로 출력되는 더 많은 정보를 확인하면 아래와 같은 정보를 얻을 수 있다.

- 파일 전송: 21번 포트에 FTP인 vsftpd 3.0.3버전
- SSH: 22포트에 OpenSSH 8.0버전
- 웹서버: 80번 포트에 Apache Tomcat 9.0.68버전
- 데이터베이스: 3306포트 mysql로 추정하나 닫혀있음
- 웹-서버 중개인: 8080포트 http-proxy로 추정하나 닫혀있음
- 운영체제: 95% 확률로 리눅스 5.1

# 3번. IP -----

![스크린샷 2022-11-11 오전 1.49.31.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/7509c37a-2ff3-44b0-90d5-54c4854bffca/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2022-11-11_%E1%84%8B%E1%85%A9%E1%84%8C%E1%85%A5%E1%86%AB_1.49.31.png)

![스크린샷 2022-11-11 오전 1.50.24.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/de4c9637-3e1b-4028-8070-c00cb1174b88/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA_2022-11-11_%E1%84%8B%E1%85%A9%E1%84%8C%E1%85%A5%E1%86%AB_1.50.24.png)

총 3가지의 포트가 있으며 80, 3306, 3389가 open상태인 것을 알 수 있다. 간략한 포맷으로 정리해본 정보들과 딕셔너리로 출력되는 더 많은 정보를 확인하면 아래와 같은 정보를 얻을 수 있다.

- 웹서버: 80번 포트에 Microsoft IIS https, 10.0버전
- 데이터베이스: 3306번 포트에 MYSQL, 8.0.31버전
- 원격데스크톱서비스: 3389포트에 Microsoft Terminal Services 원격서비스.
- 운영체제: OS는 윈도우로 추정
