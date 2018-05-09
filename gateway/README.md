# IoT-Dynamic-Profile
## Overview 
### Dependencies
This is a Python2.7 project. It uses libraries:

- [Scapy v2.x](https://github.com/secdev/scapy)
- numpy
- pymongo
- scipy

## Installation
1. Prepare environment
```BASH
sudo apt-get install curl
sudo apt install p7zip-full
```
2. Install python dependency packages listed above
3. Configure **dropbox_uploader** in the *upload_download* directory following the [instructions here](https://github.com/andreafabrizi/Dropbox-Uploader/blob/master/README.md)
4. (Optional) Install [MongoDB](https://www.mongodb.com/) locally and start MongoDB service

### Subdirectories
- manuf
    - MAC address to Vendor database
- db_config  
    - database and wrapper functions
- upload_download
    - upload function and download to and from Dropbox
    - this is third party code, please go to the foder for README and origin repository
- preprocess
    - preprocessing scripts to filter '.pcap' traffic files.

## Databse Usage
1. Current MongoDB database is deployed on cloud. To use MongoDB locally for testing,  please install MongoDB locally and start service.

2.  To Use Database in your own code (project home dir), please include the following import instructions
```python
from db_config.mongo_ops import *
```

## Feature Extractor Usage

1. Make sure the scapy installation is correct by a sanity check

```python
from scapy.all import *
```

2. To use feature extractor in your code
```python
from feature_extractor import *

feat_vec = get_features_vec(packets) 
# using default feature list, The default configuration file will be test.cfg stored in feature_extractor/config/ # folder.
feat_vec = get_features_vec(packets,fileName) 
# using self defined feature list , save the file to config/folder

feat_dict = get_features_dict(packets) 
# using default feature list, The default configuration file will be test.cfg stored in feature_extractor/config/ # folder.
feat_dict = get_features_dict(packets,fileName) 
# using self defined feature list , save the file to config/folder
```
## Upload and Download from Dropbox Usage
After configuring dropbox_uploader client in the ***upload_download*** folder, you can use the upload and download API created for this project as follows:

```Python
from upload_download.upload import upload
from upload_download.download import download

upload(iteration_number)
download(iteration_number)
```

## Project Usage

### Initialization and Pre-configuration

1. Default Mode

The project should ideally start running in a network where no devices are connected except default gateway. The joining of devices are handled properly, however the event of device leaving the network will not be handled.

2. Debug Mode

If the network is already set up and there are devices already connected to the network, the file ***device_list.txt*** can be used to initialize. You should add device's IP and MAC address in the format of '255.255.255.255,ff:ff:ff:ff:ff:ff' in lower case. 
For device that should not be monitored , ***exception_list.txt*** should be modified to add the IP address.
The debug mode is not tested fully. 

### Running Project

There are two stages of running the project
1. Learning
```bash
./run_learn.sh
```
Or change the default behavior instead of running shell scripts

```bash
python db_config/mongo_drop.py # clean up database
sudo rm -rf cap_* # clean up folder
sudo python learner.py --time 60000

```

2. Monitoring
```BASH
./run_monitor.sh
```

Or change the default behavior instead of running shell scripts
```BASH
sudo rm -rf cap_* # clean up folder
sudo python monitor.py --time 60000
```



