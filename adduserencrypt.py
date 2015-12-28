#!/usr/bin/python3
from __future__ import print_function
from subprocess import Popen, PIPE, call
import shutil
import argparse
from getpass import getpass
import os
import pexpect
import re
import tempfile
import sys
from time import sleep
parser = argparse.ArgumentParser(description='Add a new user and encrypt their home directory')
parser.add_argument('username', type=str.lower, nargs=1,
                   help='name for new user account')

#parser.add_argument('password', metavar='pass', type=str, nargs=1,
#                   help='password associated with the new user account')

parser.add_argument('--admin', dest='admin', action='store_true', default=False,
                   help='give new user admin rights (add to group "sudo")')

DEFAULT_FILES = ['.bashrc', '.xsessionrc']

class StdoutWrapper(object):
  def write(self, msg):
    return sys.stdout.write(msg.decode('utf8'))
   
  def flush(self):
    return sys.stdout.flush()

def get_user_proc_ids(user):
  out, err = Popen(['ps', '-U', user, '-o', 'pid'], stdout=PIPE).communicate()
  return out.split()[1:]

def call_or_exc(*args, **kwargs):
  if call(*args, **kwargs) != 0:
    raise ValueError('command "{}" failed'.format(args))

def find_bakdir(user):
  for home in os.listdir('/home'):
    if re.match(r'^' + user + r'\.\w+', home):
      return '/home/' + home    

def roll_back(state, child, user):
  if 6 > state > 3:
    child.sendline('logout')
    child.expect_exact('# ')
    child.terminate()
    sleep(1)
    for pid in get_user_proc_ids(user):
      call(['kill', pid])
    sleep(1)    
    call(['umount', '/home/' + user])    
    
  if state > 0:
    call(['deluser', user, '--remove-home'])
    
  if state > 2:
    home = find_bakdir(user)
    if home:
      shutil.rmtree(home)
    shutil.rmtree('/home/.ecryptfs/' + user)
def check_root_priv():
  try:
    tempfile.TemporaryFile(mode='w+b', suffix='.rootcheck', prefix='tmp', dir='/home')
  except OSError as e:
    raise OSError('Cannot write to /home, do you have root privileges? remember to run with sudo.\n\t' + str(e))
  
def make_user(user, passw, admin):
  state = 0
  child = pexpect.spawn('bash')
  child.logfile_read = StdoutWrapper()
  try:    
    check_root_priv()
    
    if not user:
      raise ValueError('user name not valid')
    
    if os.path.isdir('/home/' + user):
      raise ValueError('User home already exists!')
    
   
    # Adding user and set privileges
    child.expect_exact("# ")
    child.sendline(' '.join(['adduser', user]))
    child.expect_exact('Enter new UNIX password: ')
    child.send(passw + '\r')
    child.expect_exact('Retype new UNIX password: ')
    child.send(passw + '\r')
    for i in range(5):
      child.expect(']:')
      child.send(input() + '\r')
    child.expect('Y/n')
    child.send('y\r')    
    child.expect_exact("# ")
    state = 1
  
    if admin:
      call_or_exc(['adduser', user, 'sudo'])
      state = 2
    
    # Do encryption and check if successful
    cmd = 'ecryptfs-migrate-home -u {0}'.format(user)
    child.sendline(cmd)
    state = 2.5
    
    idx = child.expect(['ERROR: ', 'passphrase \[{0}\]:'.format(user)])
    if idx:
      child.send(passw + '\r')
    
    idx = idx or child.expect(['ERROR: ', 'Some Important Notes!'])
    if idx == 0:
      raise ValueError('error in encryption')
    
    child.expect_exact("# ")
    state = 3
    child.sendline('login {0}'.format(user))
    child.expect('Password:')
    child.send(passw + '\r')
    child.expect_exact("$ ")
    
    child.sendline("md5sum /etc/skel/.xsessionrc | awk '{ print $1 }'")
    child.expect('\w{32}')
    checksum1 = child.after
    child.expect_exact('$ ')
    
    child.sendline("md5sum .xsessionrc | awk '{ print $1 }'")
    child.expect('\w{32}')
    checksum2 = child.after
    child.expect_exact('$ ')
    
    if checksum1 != checksum2:
      raise ValueError('Encryption process failed. checksums do not match')
    state = 4
     
    # save unwrapped passphrase to current admin's home
    child.sendline('ecryptfs-unwrap-passphrase')
    child.expect('Passphrase:')
    child.send(passw + '\r')
    child.expect('\w{32}')
    unwrap = child.after
    call_user = os.environ['SUDO_USER'] if 'SUDO_USER' in os.environ and os.environ['SUDO_USER'] else os.environ['USER']
    key_dir = '/home/' + call_user + '/encryptkeys'
    if not os.path.isdir(key_dir):
      os.mkdir(key_dir)
     
    with open(key_dir + '/' + user, 'wb') as fp:
      fp.write(unwrap)
    state = 5

    # exit and clean-up
    child.sendline('exit')
    state = 6
    shutil.rmtree(find_bakdir(user))
    
  except KeyboardInterrupt:
    child.sendintr()
    child.expect('.*')
    roll_back(state, child, user)      
    print('User interruption')
   
  except Exception as e:
    roll_back(state, child, user)
    print('Error ocurred\n\t{}'.format(str(e)))
    raise e

def main():
  args = parser.parse_args()
  passw1 = getpass('password for {0}: '.format(args.username[0])) 
  passw2 = getpass('password for {0}: '.format(args.username[0])) 
  if passw1 != passw2:
    print('Passwords do not match... exiting')
  else:
    make_user(args.username[0], passw1, args.admin)

if __name__ == '__main__':
  main()