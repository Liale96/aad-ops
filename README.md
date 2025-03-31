# Usage  

#install dependency  
pip install cryptography pyjwt requests  

#Add new certificate  
python appkeys.py --client-id '' --tenant-id '' --pfx '' --pfx-password '' --app-object-id '' --new-cert ''  

#Removing existing certificate  
python appkeys.py --client-id '' --tenant-id '' --pfx '' --pfx-password '' --app-object-id '' --remove-key-id ''  
