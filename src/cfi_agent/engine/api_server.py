import os
import shutil

_TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app_template.py')


def generate_app(output_dir):
    dst = os.path.join(output_dir, 'app.py')
    shutil.copy2(_TEMPLATE, dst)
    print(f'Flask API 服务已保存: {dst}')
    return dst
