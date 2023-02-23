from distutils.core import setup

NAME = 'argo-scg'


def get_ver():
    try:
        for line in open(NAME + '.spec'):
            if "Version:" in line:
                return line.split()[1]

    except IOError:
        raise SystemExit(1)


setup(
    name=NAME,
    version=get_ver(),
    author='SRCE',
    author_email='kzailac@srce.hr',
    description='Script which generates configuration for Sensu entities, '
                'checks and namespaces on ARGO mon boxes.',
    url='https://github.com/ARGOeu/argo-scg',
    package_dir={'argo_scg': 'modules'},
    packages=['argo_scg'],
    data_files=[('/etc/argo-scg/', ['config/scg.conf'])],
    scripts=[
        'exec/scg-reload.py', 'exec/sensu2publisher.py', 'exec/scg-ad-hoc.py',
        'exec/scg-run-check.py', 'exec/scg-ack.py'
    ]
)
