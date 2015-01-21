for i in `seq 1 2`
do
echo "add alpha  127.0.0.1:30001 pvz1 0-419999" | nc 127.0.0.1 22222
echo "adddone alpha  127.0.0.1:30001 pvz1 0-419999" | nc 127.0.0.1 22222
echo "add alpha  127.0.0.1:30000 pvz1 0-419999" | nc 127.0.0.1 22222
echo "adddone alpha  127.0.0.1:30000 pvz1 0-419999" | nc 127.0.0.1 22222
echo "get alpha servers" | nc 127.0.0.1 22222
done


for i in `seq 0 10000`
do
echo "add alpha  127.0.0.1:30001 pvz1 $i-$i" | nc 127.0.0.1 22222
echo "adddone alpha  127.0.0.1:30001 pvz1 $i-$i" | nc 127.0.0.1 22222
done
echo "get alpha servers" | nc 127.0.0.1 22222
