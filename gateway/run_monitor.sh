sudo rm -rf cap_*
echo "cleaning the saved traffic data before monitoring starts"
sudo python monitor.py --debug True --time 600
