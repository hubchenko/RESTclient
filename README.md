

## RESTclient
A Python client providing primitive methods for consuming a REST API
The intent of this class is for it to be inherited by other subclasses


#### Prerequisites
* Linux Ubuntu 14.04 server
* Python 2.7


#### Installation
```bash
wget -O install.sh https://github.com/raw/hubchenko/RESTclient/master/install.sh
chmod +x install.sh
sudo ./install.sh venv
# Note: the argument venv is optional but recommended - if specified will install all packages in a Python virtual environment
```


#### Usage
```bash
$ python
>>> from RESTclient import RESTclient
>>> client = RESTclient('location of REST api', username='user', password='pass')

# GET request
>>> client.get('/rest/endpoint1')

# POST request
>>> client.post('/rest/endpoint2', json_data={'a1': 'v1'})

# PUT request with noop
>>> client.put('/rest/endpoint3', json_data={'a1': 'v1'}, noop=True)

# DELETE request with no SSL verification
>>> client.delete('/rest/endpoint4', verify=False)

```


#### Development Server Installation

Clone the repository
```bash
git clone https://github.com/hubchenko/RESTclient.git
cd RESTclient
```

Install packages and dependencies
```bash
chmod +x build.sh
sudo ./build.sh
source venv/bin/activate
```

Build the application
```bash
pyb
```

Link module for development
```bash
cd target/dist/RESTclient*/
python setup.py develop
```

Run unit tests
```bash
pyb run_unit_tests
```