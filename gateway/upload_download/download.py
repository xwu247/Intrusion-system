#!/usr/bin/python
import subprocess
import hashlib
import datetime
import sys

arch_name_template = "{0}.7z"
# arch_cmd_template = ['7z', 'x', '-mx1', '-l' ,'-p{password}', '{filename}', '-o{backup}']
arch_cmd_template = ['7z', 'x', '-mx1', '-l' ,'-p{password}', '{filename}']
#
#arch_cmd_template = ['rar', 'a', '-p{password}', '{filename}', '{backup}']
# upload_cmd = ['./dropbox_uploader.sh' ,'-f/home/vincent/.dropbox_uploader', 'upload']
upload_cmd = ['./dropbox_uploader.sh', 'download']

def main(backup, salt):
  log = open('/tmp/backup.log', 'w')
  date = datetime.date.today()
  date = date.strftime("%Y%m%d")
  zip_name = arch_name_template.format(date+"_"+salt)
  print(zip_name)
  password = "%s.%s" % (date[::-1], hashlib.sha1(salt).hexdigest())
  print(password)
  params = {'password': password, 'filename': zip_name, 'backup': backup}
  
 
  upload_cmd.append(zip_name)
  #target path
  upload_cmd.append('./')
  print(upload_cmd)
  subprocess.call(upload_cmd, stdout=log)
  
  cmd = []
  for seg in arch_cmd_template:
    cmd.append(seg.format(**params))
  print(cmd)
  subprocess.call(cmd, stdout=log)
  log.close()

def getpass(main_name):
  num = main_name[0:8][::-1]
  salt = main_name[9:]
  print num + '.' + hashlib.sha1(salt).hexdigest()

# if __name__ == "__main__":
#  if (len(sys.argv) == 3):
#    main(sys.argv[1], sys.argv[2])
#  elif (len(sys.argv) == 2):
#    getpass(sys.argv[1])
#  else:
#    print "Usage(Backup to dropbox): %s [path_to_backup] [password_salt]" % sys.argv[0]
#    print "Usage(Get password from file name): %s [main_file_name] " % sys.argv[0]
