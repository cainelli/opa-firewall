FROM cosmtrek/air

RUN wget -qO - http://packages.confluent.io/deb/3.1/archive.key | apt-key add -

RUN apt-get update && apt-get install software-properties-common -y

RUN add-apt-repository "deb [arch=amd64] http://packages.confluent.io/deb/3.1 stable main"

RUN apt-get update &&  apt-get install librdkafka-dev -y
