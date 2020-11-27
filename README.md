git clone https://github.com/SeungjunProgramming/AirplayRaspberry.git
cd RPiPlay

sudo apt-get install cmake
sudo apt-get install libavahi-compat-libdnssd-dev
sudo apt-get install libplist-dev
sudo apt-get install libssl-dev
mkdir build
cd build
cmake ..
make
