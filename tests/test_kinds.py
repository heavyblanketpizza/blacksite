import pytest

from blacksite.evidence.kinds import classify, summarize
from blacksite.evidence.parse import LineParser

PARSER = LineParser(year=2026)

DF = """\
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        40G   38G  1.1G  98% /
tmpfs           3.9G     0  3.9G   0% /dev/shm
/dev/mapper/vg-data
                200G   82G  119G  41% /data
"""
DF_INODES = """\
Filesystem      Inodes   IUsed  IFree IUse% Mounted on
/dev/sda1      2621440 2621440      0  100% /
"""
FREE = """\
               total        used        free      shared  buff/cache   available
Mem:            7937        7612          95          12         229         102
Swap:           2047        2047           0
"""
FREE_HUMAN = """\
               total        used        free      shared  buff/cache   available
Mem:           7.7Gi       7.4Gi        95Mi        12Mi       229Mi       102Mi
Swap:             0B          0B          0B
"""
PS = """\
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.1 168000 11000 ?        Ss   Oct20   0:01 /sbin/init
app         1234 98.0 61.2 9800000 4900000 ?     Rl   02:10  12:01 /usr/bin/java -Xmx4g -jar /srv/app/app.jar
postgres     990  1.2  8.0 400000 650000 ?       Ss   Oct20   1:10 postgres: checkpointer
www-data    2001  0.0  0.0      0     0 ?        Z    02:13   0:00 [php-fpm] <defunct>
"""
SS = """\
State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port  Process
LISTEN  0       511      0.0.0.0:80            0.0.0.0:*          users:(("nginx",pid=1234,fd=6))
LISTEN  0       4096     127.0.0.1:5432        0.0.0.0:*          users:(("postgres",pid=990,fd=7))
ESTAB   0       0        10.0.0.5:80           10.0.0.9:51234     users:(("nginx",pid=1235,fd=12))
CLOSE-WAIT 1    0        10.0.0.5:8080         10.0.0.9:51240
"""
NETSTAT = """\
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1234/nginx
tcp        0      0 10.0.0.5:80             10.0.0.9:51234          ESTABLISHED 1235/nginx
udp        0      0 0.0.0.0:68              0.0.0.0:*                           800/dhclient
"""
SYSTEMCTL = """\
● app.service - Order API
     Loaded: loaded (/etc/systemd/system/app.service; enabled; preset: enabled)
     Active: failed (Result: oom-kill) since Tue 2026-10-21 02:14:06 UTC; 2min ago
   Main PID: 1234 (code=killed, signal=KILL)
     Memory: 3.0G (max: 3.0G)

Oct 21 02:14:06 web1 systemd[1]: app.service: Main process exited, code=killed, status=9/KILL
Oct 21 02:14:06 web1 systemd[1]: app.service: Failed with result 'oom-kill'.
"""
UPTIME = " 02:14:05 up 3 days,  4:12,  2 users,  load average: 12.40, 8.10, 3.20\n"
NGINX_CONF = """\
# managed by ansible
worker_processes auto;
events { worker_connections 1024; }
http {
    upstream app { server 127.0.0.1:8080; }
    server {
        listen 80;
        location / { proxy_pass http://app; }
    }
}
"""
UNIT = "[Unit]\nDescription=Order API\n\n[Service]\nExecStart=/usr/bin/java -jar app.jar\nMemoryMax=3G\n"
LOG = "2026-10-21 02:14:01 INFO started\n2026-10-21 02:14:02 ERROR boom\nno time here\n"
JSON_LINES = '{"ts": "2026-10-21T02:14:01Z", "msg": "a"}\n{"ts": "2026-10-21T02:14:02Z", "msg": "b"}\n'


@pytest.mark.parametrize(("name", "text", "kind"), [
    ("df.txt", DF, "output"),
    ("pasted/01-output.txt", "$ df -h; free -m\n" + DF + "\n" + FREE, "output"),
    ("status.txt", SYSTEMCTL, "output"),
    ("uptime.txt", UPTIME, "output"),
    ("nginx/nginx.conf", NGINX_CONF, "config"),
    ("etc/systemd/system/app.service", UNIT, "config"),
    ("config.yml", "server:\n  port: 8080\ndatabase:\n  pool: 20\n", "config"),
    ("app/settings.json", '{\n  "pool": 20,\n  "timeout": 30\n}\n', "config"),
    ("app/app.log", LOG, "log"),
    ("app/events.json", JSON_LINES, "log"),
    ("notes.txt", "The deploy happened at two.\nThen it broke.\n", "log"),
    ("empty.log", "\n\n", "log"),
])
def test_classify_recognizes_logs_configs_and_command_output(name: str, text: str, kind: str) -> None:
    assert classify(name, text.splitlines(), PARSER) == kind


def test_df_facts_rank_the_fullest_filesystems_and_join_wrapped_rows() -> None:
    assert summarize(DF.splitlines()) == (["df"], ["disk: / 98% used, 1.1G free; /data 41% used, 119G free; "
                                                   "/dev/shm 0% used, 3.9G free"])
    assert summarize(DF_INODES.splitlines()) == (["df"], ["inodes: / 100% used, 0 free"])


def test_free_facts_use_available_memory() -> None:
    assert summarize(FREE.splitlines()) == (["free"], ["memory 99% used (102 of 7937 available); "
                                                       "swap 100% used (2047 of 2047)"])
    assert summarize(FREE_HUMAN.splitlines()) == (["free"], ["memory 99% used (102Mi of 7.7Gi available); no swap"])


def test_ps_facts_name_the_heaviest_processes_and_zombies() -> None:
    tools, facts = summarize(PS.splitlines())
    assert tools == ["ps"]
    assert facts == ["top memory: java 61.2% (pid 1234), postgres 8.0% (pid 990), init 0.1% (pid 1)",
                     "top cpu: java 98.0% (pid 1234), postgres 1.2% (pid 990), init 0.0% (pid 1)",
                     "4 processes, 1 zombie"]


def test_socket_facts_list_listeners_and_connection_states() -> None:
    assert summarize(SS.splitlines()) == (["ss"], ["listening: 0.0.0.0:80 (nginx, pid 1234), "
                                                   "127.0.0.1:5432 (postgres, pid 990)",
                                                   "connections: 1 ESTAB, 1 CLOSE-WAIT"])
    assert summarize(NETSTAT.splitlines()) == (["netstat"], ["listening: 0.0.0.0:80 (nginx, pid 1234)",
                                                             "connections: 1 ESTABLISHED"])


def test_service_and_load_facts() -> None:
    assert summarize(SYSTEMCTL.splitlines()) == (["systemctl"], ["app.service: failed (Result: oom-kill); "
                                                                 "main PID 1234 (code=killed, signal=KILL); "
                                                                 "memory 3.0G (max: 3.0G)"])
    assert summarize(UPTIME.splitlines()) == (["uptime"], ["load average 12.40, 8.10, 3.20; up 3 days,  4:12"])


def test_a_pasted_file_with_several_commands_yields_every_tool() -> None:
    tools, facts = summarize(("$ df -h\n" + DF + "\n$ free -m\n" + FREE + "\n" + UPTIME).splitlines())
    assert tools == ["df", "free", "uptime"] and len(facts) == 3
    assert summarize(LOG.splitlines()) == ([], [])
