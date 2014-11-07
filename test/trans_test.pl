#!/usr/bin/env perl
my $NC = {
    ip      => "127.0.0.1",
    port    => 22121,
    sport   => 22222,
    SERVERS => [
        {
            seg_start  => 0,
            seg_end    => 419999,
            old_server => [ '127.0.0.1', 30003 ],
            new_server => [ '127.0.0.1', 30004 ],
        }
    ],

};

my $stats = {
    ok =>0,
    err=>0,
    num=>0
};

sub require_ok {
    my ($k, $v1, $v2) = @_;
    $stats->{num} ++;
    if ("$v1" eq "$v2") {
        print ("ok - $stats->{num}  $k require='$v1' return='$v2'\n");
        $stats->{ok} ++;
    } else {
        print ("not ok - $stats->{num} $k require='$v1' return='$v2'\n");
        $stats->{err} ++;
    }
}
sub rediscmd {
    my ($ip, $port, $cmd, $require_o) = @_;
    my $o = `/Users/cycker/Bin/redis-cli -h $ip -p $port $cmd`;
    chomp ($o);
    $o =~ s/\r$//;
    $o =~ s/\n$//;
    
    if (scalar $require_o =~ /ARRAY/) {
        my @A = split /\n/, $o;
        for (my $i=0; $i< scalar @A; $i++) {
            require_ok ("$ip:$port mget $i", "$require_o->[$i]", "$A[$i]");
        }
        if (scalar @A == 0) {
           require_ok ("$ip:$port mget $i", "@$require_o", "@$A");
        }
    } 
    else { 
        require_ok ("$ip:$port $cmd", "$require_o", "$o"
        );
        
    }
}



my $key_prefix = 'aa';
my $key_max    = 15000;

foreach my $s ( @{ $NC->{SERVERS} } ) {
    print "OLD SERVER:$s->{old_server}->[0], s->{old_server}->[1]\n";
    print "NEW SERVER:$s->{new_server}->[0], s->{new_server}->[1]\n";
    print "\n";
    my $oldname= "$s->{old_server}->[0]:$s->{old_server}->[1]";
    my $newname= "$s->{new_server}->[0]:$s->{new_server}->[1]";
    my $ncname = "$NC->{ip}:$NC->{port}";

     #flush data
    rediscmd  ($s->{old_server}->[0],  $s->{old_server}->[1], "flushdb", 'OK') ;
    rediscmd  ($s->{new_server}->[0],  $s->{new_server}->[1], "flushdb", 'OK') ;

    #set data to old/new server
    foreach my $n ( 1 .. $key_max ) {
       my $key="$key_prefix$n";
        rediscmd  ($s->{old_server}->[0],  $s->{old_server}->[1], "set $key $key-at-$oldname", 'OK') ;
        rediscmd  ($s->{new_server}->[0],  $s->{new_server}->[1], "set $key $key-at-$newname", 'OK') ;
	}

    #get from nc, require eq  old server 
    foreach my $n ( 1 .. $key_max ) {
       my $key="$key_prefix$n";
        rediscmd  ($NC->{ip},  $NC->{port}, "get $key ", "$key-at-$oldname") ;
     }


	#make key redirect 
     foreach my $n ( 1 .. $key_max ) {
       my $key="$key_prefix$n";
       rediscmd  ($NC->{ip},  $NC->{port}, "set  $key ", "ERR wrong number of arguments for 'set' command") ;
     }
     
     #get from nc, require eq new server 
     foreach my $n ( 1 .. $key_max ) {
       my $key="$key_prefix$n";
       rediscmd  ($NC->{ip},  $NC->{port}, "get  $key ", "$key-at-$newname") ;
     }
     
     #set to  nc ,  get from new server require eq nc
     foreach my $n ( 1 .. $key_max ) {
       my $key="$key_prefix$n";
       rediscmd  ($NC->{ip},  $NC->{port}, "set  $key $key-at-$ncname", "OK") ;
       rediscmd  ($s->{new_server}->[0],  $s->{new_server}->[1], "get $key", "$key-at-$ncname") ;
     }
     
     my @mkey ;
     my @mresult ;
     my @mresult_empty ;
     foreach my $n ( 1 .. $key_max ) {
        my $key="$key_prefix$n";
        push @mkey, $key;
        push @mresult, "$key-at-$ncname";
        push @mresult_empty, "";
     }
       
     rediscmd  ($NC->{ip},  $NC->{port}, "mget @mkey", \@mresult) ;
     rediscmd  ($NC->{ip},  $NC->{port}, "del @mkey", $key_max) ;
     rediscmd  ($NC->{ip},  $NC->{port}, "mget @mkey", \@mresult_empty);
     
 

}

printf ("test:%d ok:%d err:%d\n", $stats->{ok} + $stats->{err}, $stats->{ok}, $stats->{err});
