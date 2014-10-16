kill -9 `ps -efww | grep perl | grpe autotest.pl | awk '{print $2}'`
killall -9 redis-test
killall -9 redis-server
