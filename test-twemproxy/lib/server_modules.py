#!/usr/bin/env python
#coding: utf-8
#file   : server_modules.py
#author : ning
#date   : 2014-02-24 13:00:28


import os
 

from utils import *
import conf

class Base:
    '''
    the sub class should implement: _alive, _pre_deploy, status, and init self.args
    '''
    def __init__(self, name, host, port, path):
        self.args = {
            'name'      : name,
            'host'      : host,
            'port'      : port,
            'path'      : path,

            'startcmd'  : '',     #startcmd and runcmd will used to generate the control script
            'runcmd'    : '',     #process name you see in `ps -aux`, we use this to generate stop cmd
            'logfile'   : '',
            'pidfile'   : '',
        }

    def __str__(self):
        return TT('[$name:$host:$port]', self.args)

    def deploy(self):
        logging.info('deploy %s' % self)
        self._run(TT('mkdir -p $path/bin && mkdir -p $path/conf && mkdir -p $path/log && mkdir -p $path/data ', self.args))

        self._pre_deploy()
        self._gen_control_script()

    def _gen_control_script(self):
        content = file(os.path.join(WORKDIR, 'conf/control.sh')).read()
        content = TT(content, self.args)

        control_filename = TT('${path}/${name}_control', self.args)

        fout = open(control_filename, 'w+')
        fout.write(content)
        fout.close()
        os.chmod(control_filename, 0755)

    def start(self):
        if self._alive():
            print ('%s already running' %(self) )
            return

        logging.info('starting %s' % self)
        t1 = time.time()
        sleeptime = .1

        cmd = TT("cd $path && ./${name}_control start", self.args)
        self._run(cmd)
        
        while not self._alive():
            print ('%s still not alive, sleep %s' % (self, sleeptime))
            lets_sleep(sleeptime)
            if sleeptime < 5:
                sleeptime *= 2
            else:
                sleeptime = 5
                

        t2 = time.time()
        print ('%s start ok in %.2f seconds' %(self, t2-t1) )

    def stop(self):
        cmd = TT("cd $path && ./${name}_control stop", self.args)
        self._run(cmd)
 
        t1 = time.time()
        while self._alive():
            print 'sleep at stop'
            lets_sleep()
        t2 = time.time()
        print ('%s stop ok in %.2f seconds' %(self, t2-t1) )

    def pid(self):
        cmd = TT("pgrep -f '^$runcmd'", self.args)
        return self._run(cmd)

    def status(self):
        logging.warn("status: not implement")

    def _alive(self):
        logging.warn("_alive: not implement")

    def _run(self, raw_cmd):
        ret = system(raw_cmd, logging.info)
        logging.info('return : [%d] [%s] ' % (len(ret), shorten(ret)) )
        return ret

    def clean(self):
        cmd = TT("rm -rf $path", self.args)
        self._run(cmd)

    def host(self):
        return self.args['host']

    def port(self):
        return self.args['port']

class RedisServer(Base):
    def __init__(self, host, port, path, cluster_name, server_name):
        Base.__init__(self, 'redis', host, port, path)

        self.args['startcmd']     = TT('bin/redis-server conf/redis.conf', self.args)
        self.args['runcmd']       = TT('redis-server \*:$port', self.args)
        self.args['conf']         = TT('$path/conf/redis.conf', self.args)
        self.args['pidfile']      = TT('$path/log/redis.pid', self.args)
        self.args['logfile']      = TT('$path/log/redis.log', self.args)
        self.args['dir']          = TT('$path/data', self.args)
        self.args['REDIS_CLI']    = conf.BINARYS['REDIS_CLI']

        self.args['cluster_name'] = cluster_name
        self.args['server_name']  = server_name

    def _info_dict(self):
        cmd = TT('$REDIS_CLI -h $host -p $port INFO', self.args)
        info = self._run(cmd)

        info = [line.split(':', 1) for line in info.split('\r\n') if not line.startswith('#')]
        info = [i for i in info if len(i)>1]
        return defaultdict(str, info) #this is a defaultdict, be Notice

    def _ping(self):
        cmd = TT('$REDIS_CLI -h $host -p $port PING', self.args)
        return self._run(cmd)

    def _alive(self):
        msg = self._ping()
        logging.debug("ping return %s" % msg)
        return strstr(msg, 'PONG')

    def _gen_conf(self):

        content = file(os.path.join(WORKDIR, 'conf/redis.conf')).read()
        #content = file('conf/redis.conf').read()
        return TT(content, self.args)

    def _pre_deploy(self):
        self.args['BINS'] = conf.BINARYS['REDIS_SERVER_BINS']
        self._run(TT('cp $BINS $path/bin/', self.args))

        fout = open(TT('$path/conf/redis.conf', self.args), 'w+')
        fout.write(self._gen_conf())
        fout.close()

    def status(self):
        uptime = self._info_dict()['uptime_in_seconds']
        if uptime:
            logging.info('%s uptime %s seconds' % (self, uptime))
        else:
            logging.error('%s is down' % self)

    def isslaveof(self, master_host, master_port):
        info = self._info_dict()
        if info['master_host'] == master_host and int(info['master_port']) == master_port:
            logging.info('already slave of %s:%s' % (master_host, master_port))
            return True

    def slaveof(self, master_host, master_port):
        cmd = 'SLAVEOF %s %s' % (master_host, master_port)
        return self.rediscmd(cmd)

    def rediscmd(self, cmd):
        args = copy.deepcopy(self.args)
        args['cmd'] = cmd
        cmd = TT('$REDIS_CLI -h $host -p $port $cmd', args)
        logging.info('%s %s' % (self, cmd))
        return self._run(cmd)

class Memcached(Base):
    def __init__(self, host, port, path, cluster_name, server_name):
        Base.__init__(self, 'memcached', host, port, path)

        self.args['startcmd']     = TT('bin/memcached -d -p $port', self.args)
        self.args['runcmd']       = self.args['startcmd']

        self.args['cluster_name'] = cluster_name
        self.args['server_name']  = server_name

    def _alive(self):
        cmd = TT('echo "stats" | socat - TCP:$host:$port', self.args)
        ret = self._run(cmd)
        return strstr(ret, 'END')

    def _pre_deploy(self):
        self.args['BINS'] = conf.BINARYS['MEMCACHED_BINS']
        self._run(TT('cp $BINS $path/bin/', self.args))

class NutCracker(Base):
    def __init__(self, host, port, path, cluster_name, masters, mbuf=512, verbose=5, is_redis=True):
        Base.__init__(self, 'nutcracker', host, port, path)

        self.masters = masters

        self.args['mbuf']        = mbuf
        self.args['verbose']     = verbose
        self.args['conf']        = TT('$path/conf/nutcracker.conf', self.args)
        self.args['pidfile']     = TT('$path/log/nutcracker.pid', self.args)
        self.args['logfile']     = TT('$path/log/nutcracker.log', self.args)
        self.args['status_port'] = self.args['port'] + 1000

        self.args['startcmd']    = TT('bin/nutcracker -v 11 -d -c $conf -o $logfile -p $pidfile -s $status_port -v $verbose -m $mbuf -i 1', self.args)
        self.args['runcmd']      = TT('bin/nutcracker -d -c $conf -o $logfile -p $pidfile -s $status_port', self.args)

        self.args['cluster_name']= cluster_name
        self.args['is_redis']= str(is_redis).lower()

    def _alive(self):
        return self._info_dict()

    def _gen_conf_section(self):
        num = len(self.masters)
        seg = 420000/num
        i = 0
        cfg=''
        for master in self.masters:
            start = i * seg  
            end = (i+1) * seg  - 1
            template = '    - $host:$port:1 pvz1 %d-%d 1' % (start, end)
            cfg = cfg + TT(template, master.args) + "\n"
            i+=1
        return cfg

    def _gen_conf(self):
        content = '''
$cluster_name:
  listen: 0.0.0.0:$port
  hash: fnv1a_64
  distribution: modhash
  preconnect: true
  auto_eject_hosts: false
  redis: $is_redis
  backlog: 512
  timeout: 400
  client_connections: 0
  server_connections: 1
  server_retry_timeout: 2000
  server_failure_limit: 2
  servers:
'''
        content = TT(content, self.args)
        return content + self._gen_conf_section()

    def _pre_deploy(self):
        self.args['BINS'] = conf.BINARYS['NUTCRACKER_BINS']
        self._run(TT('cp $BINS $path/bin/', self.args))

        fout = open(TT('$path/conf/nutcracker.conf', self.args), 'w+')
        fout.write(self._gen_conf())
        fout.close()

    def version(self):
        #This is nutcracker-0.4.0
        s = self._run(TT('$BINS --version', self.args))
        return s.strip().replace('This is nutcracker-', '')

    def _info_dict(self):
        logging.info("try %s %s stats" % (self.args['host'], self.args['status_port']))
        try:
            t = telnetlib.Telnet(self.args['host'], self.args['status_port'])
            t.write('stats')
            ret = t.read_all()
            logging.info ("return %s" % ret)
            
            return json_decode(ret)
        except Exception, e:
            logging.info('--- can not get _info_dict of nutcracker, [Exception: %s]' % (e, ))
            return None

    def reconfig(self, masters):
        self.masters = masters
        self.stop()
        self.deploy()
        self.start()
        logging.info('proxy %s:%s is updated' % (self.args['host'], self.args['port']))

    def logfile(self):
        return self.args['logfile']

    def cleanlog(self):
        cmd = TT("rm '$logfile'", self.args)
        self._run(cmd)

    def signal(self, signo):
        self.args['signo'] = signo
        cmd = TT("pkill -$signo -f '^$runcmd'", self.args)
        self._run(cmd)

    def reload(self):
        self.signal('USR1')


    def set_config(self, content):
        fout = open(TT('$path/conf/nutcracker.conf', self.args), 'w+')
        fout.write(content)
        fout.close()

        self.reload()

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

