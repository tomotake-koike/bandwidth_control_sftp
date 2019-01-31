import sys
from bandwidth_control_paramiko import BCSSHClient
from paramiko import SSHClient, AutoAddPolicy

HOST = 'localhost'
PORT = 22
USER = 'tomotake'
PRIVATE_KEY = '/home/tomotake/.ssh/id_rsa'

ssh = BCSSHClient( )
ssh.set_missing_host_key_policy(AutoAddPolicy())
print( sys.argv[1] )
ssh.connect(HOST, PORT, USER, key_filename=PRIVATE_KEY, limit=float( sys.argv[1] ) )
sftp = ssh.open_sftp()

sftp.get( '/tmp/in.dat', '/tmp/out.dat' )

sftp.close()
ssh.close()

