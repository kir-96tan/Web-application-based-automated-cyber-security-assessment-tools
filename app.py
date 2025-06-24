from flask import Flask, render_template, request, redirect
from scapy.all import *
import nmap

app = Flask(__name__)

Pak = []

def packet_display(pkt):
    Pak.append(pkt.summary())

usern = "root"
passw = "root"

@app.route('/')
@app.route('/home')
def index():
    return render_template("firstpage.html")

@app.route('/members')
def memeber():
    return render_template("member.html")

@app.route('/logout')
def logout():
    return redirect("home")

@app.route('/tester', methods=['POST','GET'])
def tester():
    if request.method == 'POST':
        user:str = request.form['username'] 
        pasw:str = request.form['password']
        if user == usern and pasw == passw:
            return redirect("optionList")
        else:
            return f"login failed ERROR 404"

@app.route('/optionList')
def optionList():
    return render_template("options.html")

@app.route('/submit', methods=['POST'])
def submit():
    scan_type = request.form.get('scan_type')
    if scan_type == "Port Scan":
        return render_template("port_scan.html")
    elif scan_type == "Host Discovery":
        return render_template("host_discovery.html")
    elif scan_type == "Packet Capturing":
        return render_template("pkgcap.html")
    elif scan_type == "Footprinting":
        return render_template("Footprinting.html")
    

@app.route('/Pscan', methods=['POST'])
def Prt():
    ip_address = request.form.get('ip_address')
    scan_type = request.form.get('scan_type')
    scanner = nmap.PortScanner()
    a = f'performing your scan>>>>>>>>>>>>>'
    b = f'---------------------------------'

    if scan_type == "SYN_ACK":
        scanner.scan(ip_address,'1-1024','-v -sS')
        c = scanner.scaninfo()
        d = f"Ip Status:,{scanner[ip_address].state()}"
        e = f"{scanner[ip_address].all_protocols()}"
        f = f"Open Port:,{scanner[ip_address]['tcp'].keys()}"
        return render_template("result.html",a=a,b=b,c=c,d=d,e=e,f=f)
        
    elif scan_type == "UDP":
        scanner.scan(ip_address,'1-1024','-v -sU')
        c = scanner.scaninfo()
        d = f"Ip Status:,{scanner[ip_address].state()}"
        e = f"{scanner[ip_address].all_protocols()}"
        f = f"Open Port:,{scanner[ip_address]['udp'].keys()}"
        return render_template("result.html",a=a,b=b,c=c,d=d,e=e,f=f)
        
    elif scan_type == "TCP":
        scanner.scan(ip_address,'1-1024','-v -sT')
        c = scanner.scaninfo()
        d = f"Ip Status:,{scanner[ip_address].state()}"
        e = f"{scanner[ip_address].all_protocols()}"
        f = f"Open Port:,{scanner[ip_address]['tcp'].keys()}"
        return render_template("result.html",a=a,b=b,c=c,d=d,e=e,f=f)



@app.route("/Hdscan", methods = ['POST'])
def hds():
    ip_add = request.form["IP"]
    p = request.form["bits"]
    ip = str(ip_add) + "/" + str(p)
    nm = nmap.PortScanner()
    nm.scan(hosts=ip,arguments="-sn")
    lis = [(x,nm[x]['status']['state']) for x in nm.all_hosts()]
    return render_template('hdresult.html',lis=lis)


@app.route("/footing", methods = ['POST'])
def foting():
    target = request.form["IP"]
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-A')
    
    for host in nm.all_hosts():
        lis=[]
        a = f"Host: {host} ({nm[host].hostname()})"
        b = f"State: {nm[host].state()}"
        for proto in nm[host].all_protocols():
            c = f"Protocol: {proto}"
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                bis = []
                d = f"Port: {port}\tState: {nm[host][proto][port]['state']}"
                if 'version' in nm[host][proto][port]:
                    e = f"Version: {nm[host][proto][port]['version']}"
                if 'product' in nm[host][proto][port]:
                    f = f"Product: {nm[host][proto][port]['product']}"
                if 'extrainfo' in nm[host][proto][port]:
                    g = f"Extra Info: {nm[host][proto][port]['extrainfo']}"
                if 'reason' in nm[host][proto][port]:
                    h = f"Reason: {nm[host][proto][port]['reason']}"
                if 'cpe' in nm[host][proto][port]:
                    i = f"CPE: {nm[host][proto][port]['cpe']}"
                bis.append(d)
                bis.append(e)
                bis.append(f)
                bis.append(g)
                bis.append(h)
                bis.append(i)
                lis.append(bis)
    return render_template("footresult.html", a=a , b=b , c=c ,lis = lis)


@app.route("/pkgcap", methods = ['POST'])
def pcap():
    c = int(request.form["PAK"])
    sniff(count = c, prn=packet_display)
    return render_template("pkgresult.html",Pak=Pak)


if __name__ == "__main__":
    app.run(debug=True)
 
