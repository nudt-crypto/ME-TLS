ME-TLS source code, based on tlslite-ng implementation of TLS 1.3.

---------------------------------------------------------------------------
Environment Setup:
sudo yum install openssl-devel
sudo apt-get install python-pip
sudo yum install python-devel
sudo yum install gmp-devel
sudo pip install virtualenv

then install pbc:
unpack pbc, cd into the directory
./configure --prefix=$HOME/.local
make
sudo make install

then install charm crypto:
unpack charm, cd into the dir
./configure.sh
sudo make install
then before using charm:
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:~/.local/lib

Users are encouraged to use virtualenv:
first virtualenv somedir, activate it: source somedir/bin/activate
then: pip install six ecdsa selectors2 pycrypto M2Cryto gmpy ipaddress
then python setup.py install (to install metls)

Sometimes we need to shutdown the OS firewall
in CentOS 7: sudo systemctl stop firewalld

Have Fun!
