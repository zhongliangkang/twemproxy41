#!/usr/bin/env perl
use strict;
use FindBin qw($Bin);
use POSIX qw(strftime);
use Time::Local;


sub nowtime {
   my $t = shift || time;
   my @n = localtime($t);
   return  sprintf("%04d-%02d-%02d %02d:%02d:%02d",$n[5]+1900,$n[4]+1,$n[3], $n[2], $n[1], $n[0] );
}

sub print_log {
    my $time     = nowtime();
    print "[$time][$$] @_";
}


use strict;
sub start_redis {
	my $port=shift;
   my $o=`./redis-server --port $port >log/$port.log 2>&1 &`;
	
}

sub stop_redis {
	my $port=shift;
   my $o=`./redis-cli -p $port shutdown`;
	
}

sub check_process {
   my $process=shift;
   my $port=shift;
	my $name = substr $process, 0, 8;
   for my $l (`lsof -i:$port | grep $name | grep LISTEN`) {
		my @f = split /\s+/, $l;
		return $f[1];
	}
	return 0;	
	
		
}

sub dbsize {
   my $port=shift;
   my $dbsize=`./redis-cli -p $port dbsize 2>&1`;
   chomp $dbsize;
   return $dbsize;
#   echo "check_redis port $port dbsize $dbsize"
}

my $pid = check_process "nutcracker", 22121;
if ($pid) {
	print_log ("kill nutcracker 22121\n");
	kill 9, $pid;
}
print_log ("start nutcracker 22121\n");
` cp nutcracker.yml.trans conf/nutcracker.yml`;
`./nutcracker -d -o twemproxy.log -s 23121`;
sleep 1;

print_log ("start redis 6379\n");
	if (check_process("redis-server",6379)) {
		stop_redis 6379;
	}
start_redis 6379;
sleep 1;

my $MAX_KEY_NUM= 1000000;
print_log "fill redis 6379 to $MAX_KEY_NUM keys\n";
my $dbsize = 0;
my $cmd = "./create_key -h 127.0.0.1 -p 22121 -n $MAX_KEY_NUM -c 'set k\%k k\%k' >/dev/null 2>&1";
print_log ($cmd, "\n");
`$cmd`;
$dbsize = dbsize 6379;
if ($dbsize  != $MAX_KEY_NUM) {
	print_log  ("fill redis 6379 failed, exit\n");
	exit(1);
}

my $pid1;

if (($pid1 = fork()) == 0) {
	
		unlink ("test_get.log") if (-f "test_get.log");
		print_log ("do redis-test in sub porcess\n");
		my $testcmd =" ./redis-test -h 127.0.0.1 -p 22121 -n 10000000 -c 100  -r 1000000 get k__rand_int__  >/dev/null 2>>test_get.log";
		while  (1) {
			my $t1 = time;
			`$testcmd`;
			my $t2 = time - $t1;
			my $qps =  sprintf ("%d\n", $MAX_KEY_NUM / $t2);
			print_log ("do redis-test -n 10000000 use ", $t2 , " seconds, qps is $qps\n");
			if ($t2 < 10) {
				sleep 1;
			}
		}
		
        exit 0;
}




for (my $p=6379;$p<9999;$p++) {
	my $p1 = $p+1;
	if (check_process("redis-server",$p1)) {
		stop_redis $p1;
	}
	print_log ("start redis $p1\n");
	start_redis $p1;
	sleep 1;
	my $ok = 0;
	for my $x (0..10) {
		my $pid = check_process "redis-server", $p1;
		if ($pid > 0) {
			print_log ("start redis $p1 success\n");
			$ok = 1;
			last;
		}
	}

	if ($ok == 0) {
		print_log ("start redis $p1 failed, exit\n");
		exit(1);
	}
	
	my $dbsize = dbsize $p;
	my $p1dbsize = dbsize $p1;
	print_log ("before transfer,   $p dbsize: $dbsize, $p1 dbsize:  $p1dbsize\n"); 
	my $cmd = "./transfer twemproxy-list 127.0.0.1:$p 127.0.0.1:$p1 0 419999 >o$p 2>&1";
	print_log $cmd, "\n";
	`$cmd`;
	my $dbsize_2 = dbsize $p;
	my $p1dbsize_2 = dbsize $p1;
	print_log ("after transfer,   $p dbsize: $dbsize_2, $p1 dbsize:  $p1dbsize_2\n"); 
	if ($p1dbsize_2 ne $dbsize or $dbsize_2 ne $p1dbsize) {
		print_log ("transfer error, exit\n");	
		exit;
	}

	#`gzip "o$p"`;
	unlink ("o$p"); #rm transfer log
	stop_redis $p;
}

kill 9, $pid;
