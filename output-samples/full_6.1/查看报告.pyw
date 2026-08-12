# -*- coding: utf-8 -*-
import os, sys, subprocess, time, webbrowser, urllib.request
d = os.path.dirname(os.path.abspath(__file__))
def running():
    try:
        urllib.request.urlopen("http://127.0.0.1:5000/api/summary", timeout=2).read()
        return True
    except:
        return False
if not running():
    subprocess.Popen([sys.executable, "app.py"], cwd=d,
        creationflags=0x00000008|0x00000200|0x08000000,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(20):
        time.sleep(0.5)
        if running(): break
webbrowser.open("http://127.0.0.1:5000")
