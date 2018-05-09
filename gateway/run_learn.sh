python db_config/mongo_drop.py
echo "_______cleaning up database________"
sudo rm -rf cap_*
echo "_______cleaning saved traffic files before learning start______"
sudo python learner.py --debug True --time 1000
