
import traceback
import os
import sys
import socket
import time


Tversion = 100
Rversion = 101
Tauth = 102
Rauth = 103
Tattach = 104
Rattach = 105
Terror = 106
Rerror = 107
Tflush = 108
Rflush = 109
Twalk = 110
Rwalk = 111
Topen = 112
Ropen = 113
Tcreate = 114
Rcreate = 115
Tread = 116
Rread = 117
Twrite = 118
Rwrite = 119
Tclunk = 120
Rclunk = 121
Tremove = 122
Rremove = 123
Tstat = 124
Rstat = 125
Twstat = 126
Rwstat = 127
MAX_MSIZE = 32768


Oread		= 0x00
Owrite		= 0x01
Ordwr		= 0x02
Oexec		= 0x03
Oexcl		= 0x04
Otrunc		= 0x10
Orexec		= 0x20
Orclose		= 0x40
Oappend		= 0x80


def printf(format, *args):
    sys.stdout.write(format % args)

global RootPath
RootPath = "d:/"

def itob(n, a):
    return a.to_bytes(n, "little")

def btoi(b):
    return int.from_bytes(b, "little")

def strtob(s):
    s = s.encode(encoding='UTF-8')
    return itob(2, len(s))+s

class Qid():
    path = 0
    version = 0
    type = 0

    def tob(self):
        res = itob(1, self.type)
        res = res + itob(4, self.version)
        res = res + itob(8, self.path)
        return res


class Stat():
    fid = 0
    type = 0
    dev = 0
    qid = Qid()
    mode = 0
    atime = 0
    mtime = 0
    lengh = 0
    name = "/"
    uid = "???"
    gid = "???"
    muid = ""

    def serialize(self):

        stats = itob(2, self.type)+itob(4, self.dev)+self.qid.tob() + \
            itob(4, self.mode)+itob(4, self.atime)+itob(4, self.mtime)

        stats = stats + itob(8, self.lengh)+strtob(self.name) + \
            strtob(self.uid)+strtob(self.gid)+strtob(self.muid)

        return itob(2, len(stats)) + stats
    
    def tob(self):
        stats = self.serialize()
        return itob(2,len(stats))+stats


class Record():
    path = ""
    childs = []
    fetch_idx = 0
    fd = -1
    
    def clear(self):
        self.path = ""
        self.childs = []
        self.fetch_idx = 0
        self.fd = -1
    def clone(self):
        res = Record()
        res.path = self.path
        return res


global fidpool
fidpool={}

def get_fid_item(fid):
    global fidpool
    return fidpool[fid]

def add_fid_item(k,v):
    global fidpool
    fidpool[k]=v

def del_fid_item(k):
    global fidpool
    del fidpool[k]

class Bufp():
    data = b''

    def get_int(self, wordlen):
        res = btoi(self.data[0:wordlen])
        self.data = self.data[wordlen:]
        return res

    def get_str(self):
        size = btoi(self.data[0:2])
        str = self.data[2:size+2].decode()
        self.data = self.data[size+2:]
        return str
    
    def get_binary(self,n):
        dt = self.data[0:n]
        self.data = self.data[n:]
        return dt


def get_real_name(path):
    sz = len(path)
    lst = []
    i = sz-1
    res = ""
    while i >= 0:
        if path[i] != '/':
            break
        i = i - 1
    while i >= 0:
        if path[i] == '/':
            break
        lst.append(path[i])
        i = i - 1
    i = len(lst) - 1
    while i >= 0:
        res = res + lst[i]
        i = i - 1
    return res


def getStat(path, fid):
    ss = Stat()
    st = os.stat(path)
    ss.atime = int(st.st_atime)
    ss.mtime = int(st.st_mtime)
    ss.lengh = int(st.st_size)
    ss.mode = int(st.st_mode)
    ss.dev = int(st.st_dev)
    ss.fid = fid
    ss.name = get_real_name(path)
    ss.qid.version = int(st.st_mtime) ^ (st.st_size << 8)
    ss.qid.version = ss.qid.version & 0xffffffff
    ss.qid.path = int(st.st_ino)
    if os.path.isdir(path):
        ss.qid.type = 0x80
        ss.mode = 33204 | 0x80000000
    else:
        ss.mode = 33279
        ss.qid.type = 0
    return ss


def getqid(path, fid):

    ss = getStat(path, fid)

    return ss.qid

def fetch_dir(path):
    ary = os.listdir(path)
    res = []
    kk = b''
    for f in ary:
        try:
            kk = getStat(path+"/"+f, 0).serialize()
        except:
            pass
        else:
            res.append(kk)
    return res

def readn(conn: socket.socket, n):
    left = n
    res = b''
    while left > 0:
        data = conn.recv(left)
        if data == b'':
            break
        res = res + data
        left = left - len(data)
    return res

def get_mode(mod):
    x = mod &3
    str=""
    if x==Oread:
        str = "rb"
    elif x== Ordwr:
        str = "rb+" 
    elif x== Owrite:
        str = "rb+"  
    elif x== Oexec:
        str = "rb"
    else:
        str = "rb"
    return str

def msg_common(size,cmd,tag):
    return itob(4, size)+itob(1, cmd)+itob(2, tag) 


# T size[4] cmd[1] tag[2] fid[4]
# R size[4] cmd[1] tag[2] stat
def fRstat(conn: socket.socket, tag, buf: Bufp):
    fid = buf.get_int(4)
    s = get_fid_item(fid)
    dt = getStat(s.path, fid).tob()
    size = 4+1+2+len(dt)
    res = msg_common(size,Rstat,tag)+dt
    conn.send(res)

 # T  size[4] cmd[1] tag[2] msize[4] version[s]
 # R  size[4] cmd[1] tag[2] msize[4] version[s]
def fRversion(conn: socket.socket, tg, buf: Bufp):
    version = "9P2000"
    ms = buf.get_int(4)
    printf("get ms %d\n",ms)
    if ms > MAX_MSIZE:
        ms = MAX_MSIZE
    size = 4 + 1 + 2 + 4 + len(strtob(version))
    msize = ms
    res = msg_common(size,Rversion,65535) + itob(4, msize) + strtob(version)
    conn.send(res)


# T size[4] cmd[1] tag[2] fid[4] afid[4] uname[s] aname[s]
# R size[4] cmd[1] tag[2] qid[13]
def fAttach(conn: socket.socket, tg, buf: Bufp):
    fid = buf.get_int(4)
    q = getqid(RootPath, fid)
    size = 4 + 1 + 2 + 13
    res = msg_common(size,Rattach,tg)+q.tob()
    r = Record()
    r.path = RootPath
    add_fid_item(fid,r)
 
    conn.send(res)

# T size[4] cmd[1] tag[2] fid[4] newfid[4] nwname[2] name[s]*
# R size[4] cmd[1] tag[2] mwqid[2] qid[13]*
def fRwalk(conn: socket.socket, tag, buf: Bufp):
    fid = buf.get_int(4)
    newfid = buf.get_int(4)
    rootdir = get_fid_item(fid)
#    printf("walk fid %d newfid %d\n",fid,newfid)
    if newfid == fid:
        newdir = rootdir
        printf("## same fid %d\n",fid)
    else:
        newdir = rootdir.clone()
    add_fid_item(newfid,newdir)
    n = buf.get_int(2)
    qids = []
    path = newdir.path
    for i in range(n):
        name = path + "/" + buf.get_str()
        try:
            st = os.stat(name)
        except:
            break
        path = name
        q = getqid(name, 0)
        qids.append(q)
        if q.type == 0:
            break
    nqids = len(qids)
    newdir.path = path
    sz = 4+1+2+2+nqids*13
    res = msg_common(sz,Rwalk,tag)+ itob(2, nqids)
    
    for k in qids:
        res = res + k.tob()
    
    conn.send(res)

# T size[4] cmd[1] tag[2] fid[4] mode[1]
# R size[4] cmd[1] tag[2] qid[13] iounit[4]
def fRopen(conn: socket.socket, tag, buf: Bufp):
    fid = buf.get_int(4)
    mode = buf.get_int(1)
    s = get_fid_item(fid)

    qid = getqid(s.path, 0)
    
    if qid.type == 0:
        s.fd = open(s.path, get_mode(mode))
    size = 4+1+2+13+4
    res =  msg_common(size,Ropen,tag) + qid.tob()+itob(4, 0)
    conn.send(res)

# T size[4] cmd[1] tag[2] fid[4] offset[8] count[4]
# R size[4] cmd[1] tag[2] count[4] data[count]
def fRread(conn: socket.socket, tag, buf: Bufp):
    fid = buf.get_int(4)
    offset = buf.get_int(8)
    cnt = buf.get_int(4)
    s = get_fid_item(fid)

    if not os.path.isdir(s.path):
       
        if s.fd != -1:
           
            s.fd.seek(offset,0)
            res = s.fd.read(cnt)
           
        else:
            res=b''
        size = 4+1+2+4+len(res)
    #    printf("read %s offset %d size %d  tag %d\n",s.path,offset,len(res),tag)
        res =  msg_common(size,Rread,tag) + itob(4, len(res))+res
        conn.send(res)
        return

    if offset == 0:
        s.childs = fetch_dir(s.path)
        s.fetch_idx = 0

    res = b''
    count = 0
    while s.fetch_idx < len(s.childs):
        if count + len(s.childs[s.fetch_idx]) > cnt:
            break
        res = res + s.childs[s.fetch_idx]
        count = count + len(s.childs[s.fetch_idx])
        s.fetch_idx = s.fetch_idx + 1
    size = 4+1+2+4+count
    res = msg_common(size,Rread,tag) + itob(4, count)+res
    conn.send(res)

# T size[4] cmd[1] tag[2] fid[4] 
# R size[4] cmd[1] tag[2] 
def fRclunk(conn: socket.socket, tag, buf: Bufp):
    fid = buf.get_int(4)
    size = 4+1+2
    res =  msg_common(size,Rclunk,tag)
    
    s =  get_fid_item(fid)
   # printf("clunk %d %s\n",fid,s.path)
    if s.fd != -1:
        s.fd.close()
    del_fid_item(fid)
    conn.send(res)

# T size[4] cmd[1] tag[2] oldtag[2] 
# R size[4] cmd[1] tag[2] 
def fRflush(conn: socket.socket, tag, buf: Bufp):
    size = 4+1+2
    res =  msg_common(size,Rflush,tag)
    conn.send(res)

# T size[4] cmd[1] tag[2] fid[4] name[s] perm[4] mode[1]
# R size[4] cmd[1] tag[2] qid[13] iounit[4]
def fRcreate(conn: socket.socket, tag, buf: Bufp):
    fid = buf.get_int(4)
    name = buf.get_str()
    perm = buf.get_int(4)
    mode = buf.get_int(1)
    s = get_fid_item(fid)
    name = s.path+"/"+name
    s.clear()
    s.path = name
    if perm & 0x80000000:
        os.mkdir(name)
    else:
        s.fd = open(s.path,"x")
        s.fd.close()
        s.fd = open(s.path,get_mode(mode))
    qid = getqid(name,fid)
    size = 4+1+2+13+4
    res =  msg_common(size,Rcreate,tag)+qid.tob()+itob(4,0)
    conn.send(res)

# T size[4] cmd[1] tag[2] fid[4] stat[n]
# R size[4] cmd[1] tag[2] 
def fRwstat(conn: socket.socket, tag, buf: Bufp):
    fid = buf.get_int(4)
    skip = buf.get_binary(2+2+2+4+13+4+4+4)
    length = buf.get_int(8)
    s = get_fid_item(fid)
    if s.fd != -1:
        s.fd.truncate(length)
    size = 4+1+2
    res = msg_common(size,Rwstat,tag)
    conn.send(res)    

# T size[4] cmd[1] tag[2] fid[4] 
# R size[4] cmd[1] tag[2] 
def fRremove(conn: socket.socket, tag, buf: Bufp):
    fid = buf.get_int(4)
    s =get_fid_item(fid)
    os.remove(s.path)
    del_fid_item(fid)
    size = 4+1+2
    res =  msg_common(size,Rremove,tag)
    conn.send(res)      

# T size[4] cmd[1] tag[2] fid[4] offset[8] count[4] data[count]
# R size[4] cmd[1] tag[2] count[4]
def fRwrite(conn: socket.socket, tag, buf: Bufp):
    fid = buf.get_int(4)
    offset = buf.get_int(8)
    count  = buf.get_int(4)
    data = buf.get_binary(count)
    s = get_fid_item(fid)
   
    s.fd.seek(offset,0)
    n = s.fd.write(data)
    
    size = 4+1+2+4
#    printf("write %s offset %d size %d tm %f\n",s.path,offset,n,ts)
    res =  msg_common(size,Rwrite,tag)+itob(4,n)
    conn.send(res)  

FunTable = {
    Tversion: fRversion,
    Tattach: fAttach,
    Tstat: fRstat,
    Twalk: fRwalk,
    Topen: fRopen,
    Tread: fRread,
    Tclunk: fRclunk,
    Tflush: fRflush,
    Tcreate:fRcreate,
    Twstat:fRwstat,
    Tremove:fRremove,
    Twrite:fRwrite
}

def ninep(conn, address):
    buf = Bufp()
    nn=0
    while True:
        #printf("read sz\n");
        size = btoi(readn(conn, 4))
        if size < 4 or size > MAX_MSIZE:
            printf("get size error %d\n",size)
            return
        #printf("read data %d\n",nn);
        data = readn(conn, size-4)
        if len(data) != size-4:
            printf("get data error want %d get %d\n",size-4,len(data))
            return
        #print("process data\n")
        nn = nn +1
        buf.data = data
        cmd = buf.get_int(1)
        tag = buf.get_int(2)
        FunTable[cmd](conn, tag, buf)


def server_program(path):
    # get the hostname
    global RootPath
    port = 60000  # initiate port no above 1024
    RootPath = path

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # get instance

    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    # look closely. The bind() function takes tuple as argument
    # bind host address and port together
    res = server_socket.bind(("0.0.0.0", port))
    print(res)
   
    server_socket.listen(2)

    # configure how many client the server can listen simultaneously
    
    while True:
        global fidpool
        fidpool = {}
        conn, address = server_socket.accept()  # accept new connection
        print("Connection from: " + str(address))
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        try:
            ninep(conn, address)
        except Exception as e:
            printf("Unexpected exception\n")
            traceback.print_exc()
        finally:
            printf("finally\n")
            for k in fidpool:
                print(k,fidpool[k].path)
            conn.close()
            printf("fin\n")

if len(sys.argv) >=2:
    server_program(sys.argv[1])
else:
    server_program(RootPath)
