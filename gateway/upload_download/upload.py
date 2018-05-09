#!/usr/bin/python
import subprocess
import hashlib
import datetime
import sys
def main(backup, salt, iteration):
  log = open('/tmp/backup.log', 'w')
  date = datetime.date.today()
  date = date.strftime("%Y%m%d")
  zip_name = '/tmp/' +'cap' + '_'+ str(iteration) + '_' +  arch_name_template.format(date+"_"+salt);
  password = "%s_%s" % (date[::-1], hashlib.sha1(salt).hexdigest())
  params = {'password': password, 'filename': zip_name, 'backup': backup}
  
  cmd = []
  for seg in arch_cmd_template:
    cmd.append(seg.format(**params))
  subprocess.call(cmd, stdout=log)
  print(cmd)  
  upload_cmd.append(zip_name)
  #target path
  upload_cmd.append('/')
  subprocess.Popen(upload_cmd, stdout=log)
  log.close()

def upload(backup, salt, iteration):

  arch_name_template = "{0}.7z"
  arch_cmd_template = ['7z', 'a', '-mx1', '-l' ,'-p{password}', '{filename}', '{backup}']
  #arch_cmd_template = ['rar', 'a', '-p{password}', '{filename}', '{backup}']
  # upload_cmd = ['/usr/local/bin/dropbox_uploader.sh' ,'-f/home/vincent/.dropbox_uploader', 'upload']
  upload_cmd = ['./upload_download/dropbox_uploader.sh' , 'upload']


  log = open('/tmp/backup.log', 'w')
  date = datetime.date.today()
  date = date.strftime("%Y%m%d")
  zip_name = '/tmp/' +'cap' + '_'+ str(iteration) +'_' +   arch_name_template.format(date+"_"+salt);
  password = "%s_%s" % (date[::-1], hashlib.sha1(salt).hexdigest())
  password = 'traffic'
  params = {'password': password, 'filename': zip_name, 'backup': backup}
  
  cmd = []
  for seg in arch_cmd_template:
    cmd.append(seg.format(**params))
  subprocess.call(cmd, stdout=log)
  print(cmd) 
  upload_cmd.append(zip_name)
  #target path
  print("zipped returned")
  upload_cmd.append('/')
  subprocess.Popen(upload_cmd, stdout=log)
  log.close()
  print("upload finished")

def getpass(main_name):
  num = main_name[0:8][::-1]
  salt = main_name[9:]
  print num + '.' + hashlib.sha1(salt).hexdigest()

# if __name__ == "__main__":
#   if (len(sys.argv) == 3):
#     main(sys.argv[1], sys.argv[2])
#   elif (len(sys.argv) == 2):
#     getpass(sys.argv[1])
#   else:
#    print "Usage(Backup to dropbox): %s [path_to_backup] [password_salt]" % sys.argv[0]
#    print "Usage(Get password from file name): %s [main_file_name] " % sys.argv[0]
