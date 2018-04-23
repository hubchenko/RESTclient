import re
from setuptools import setup

with open('requirements.txt') as handle:
    contents = handle.read().split('\n')

requires = []
links = []
regex = '.*#egg=(?P<package>[A-Za-z]+).*'
for content in contents:
    match = re.match(regex, content)
    if match:
        requires.append(match.group('package'))
        links.append(content.replace('-e ', ''))
    else:
        requires.append(content)

print 'requires: {}'.format(requires)
print 'links: {}'.format(links)

setup(
    name='RESTclient',
    version='1.0.5',
    author='Emilio Reyes, Mark Hubchenko',
    author_email='emilio.reyes@intel.com, mark.hubchekno@gmail.com',
    package_dir={
        '': 'src/main/python'
    },
    packages=[
        'RESTclient'
    ],
    url='https://github.com/hubchenko/RESTclient',
    description='A Python client providing primitive methods for consuming a REST API',
    install_requires=requires,
    dependency_links=links
)
