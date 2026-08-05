import os
import sys
import subprocess


def generate_bat_files(output_dir):
    bat_start = os.path.join(output_dir, '启动服务.bat')
    with open(bat_start, 'w', encoding='gbk') as f:
        f.write('@echo off\r\n')
        f.write('cd /d "%~dp0"\r\n')
        f.write('python app.py\r\n')
        f.write('pause\r\n')

    bat_stop = os.path.join(output_dir, '停止服务.bat')
    with open(bat_stop, 'w', encoding='gbk') as f:
        f.write('@echo off\r\n')
        f.write('for /f "tokens=5" %%a in (\'netstat -ano ^| findstr ":5000.*LISTENING"\') do taskkill /f /pid %%a\r\n')
        f.write('echo 服务已停止\r\n')
        f.write('pause\r\n')
    return bat_start, bat_stop


def start_service(output_dir):
    import time
    import urllib.request
    DETACHED_PROCESS = 0x00000008
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    CREATE_NO_WINDOW = 0x08000000
    proc = subprocess.Popen(
        [sys.executable, 'app.py'],
        cwd=output_dir,
        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(15):
        time.sleep(0.5)
        try:
            urllib.request.urlopen('http://localhost:5000/api/summary', timeout=1).read()
            break
        except Exception:
            continue
    return proc.pid


def stop_service():
    try:
        out = subprocess.check_output(
            'netstat -ano | findstr ":5000.*LISTENING"',
            shell=True,
        ).decode('gbk', errors='ignore')
        killed = []
        for line in out.splitlines():
            parts = line.split()
            if parts:
                pid = parts[-1]
                subprocess.run(['taskkill', '/f', '/pid', pid], capture_output=True)
                killed.append(pid)
        return killed
    except subprocess.CalledProcessError:
        return []
    except Exception as e:
        return [f'error: {e}']
