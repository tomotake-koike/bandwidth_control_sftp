import socket
import threading
import time

from paramiko.channel import Channel
from paramiko.client import SSHClient
from paramiko.agent import Agent
from paramiko.common import DEBUG
from paramiko.config import SSH_PORT
from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.ed25519key import Ed25519Key
from paramiko.hostkeys import HostKeys
from paramiko.py3compat import string_types
from paramiko.rsakey import RSAKey
from paramiko.ssh_exception import (
    SSHException,
    BadHostKeyException,
    NoValidConnectionsError,
)
from paramiko.util import retry_on_signal, ClosingContextManager
from paramiko.transport import Transport
from paramiko.message import Message
from paramiko.common import (
    cMSG_CHANNEL_REQUEST,
    cMSG_CHANNEL_WINDOW_ADJUST,
    cMSG_CHANNEL_DATA,
    cMSG_CHANNEL_EXTENDED_DATA,
    DEBUG,
    ERROR,
    cMSG_CHANNEL_SUCCESS,
    cMSG_CHANNEL_FAILURE,
    cMSG_CHANNEL_EOF,
    cMSG_CHANNEL_CLOSE,
)
from paramiko.common import cMSG_CHANNEL_OPEN
from paramiko.buffered_pipe import BufferedPipe, PipeTimeout

readable_size = 0.0
start = 0.0
LOCK = threading.Lock()

class BCChannel( Channel ):
    
    def set_limit( self, limit ):
        self.limit = limit
        
    def recv(self, nbytes):
        """
        Receive data from the channel.  The return value is a string
        representing the data received.  The maximum amount of data to be
        received at once is specified by ``nbytes``.  If a string of
        length zero is returned, the channel stream has closed.
        
        :param int nbytes: maximum number of bytes to read.
        :return: received data, as a ``str``/``bytes``.
        
        :raises socket.timeout:
            if no data is ready before the timeout set by `settimeout`.
        """
        with LOCK:
            global start
            global readable_size
            out = bytes()

            limit = 100.0
            if self.limit is not None:
                limit = self.limit
            
            try:

                read_size = nbytes
                while True:
                
                    current = time.time()

                    if current - start >= 1.0:
                        start = current
                        readable_size = int( limit * 1024 * 1024 / 8 )

                    elif readable_size == 0.0:
                        # print( threading.current_thread().name + " " + str(current) + " SLEEP: " + str( 1.0 - ( current - start ) ) + " Mbps: " + str( limit / ( current - start )  ) + " Setting Mbps: " + str( limit ) )
                        time.sleep( 1.0 - ( current - start )  )
                        start = current = time.time()
                        readable_size = int( limit * 1024 * 1024 / 8 )

                    if read_size > readable_size :
                        read_size = readable_size
                    
                    readable_size -= read_size

                    # print( str(current) + " READ: " + str( read_size )  + " READABLE: " + str( readable_size ) )

                    o = self.in_buffer.read( read_size, self.timeout)
                    out += o
    
                    if len( out ) >= nbytes:
                        break
    
                    read_size = nbytes - len( out )
    
                    
            except PipeTimeout:
                raise socket.timeout()
    
            ack = self._check_add_window(len(out))
            # no need to hold the channel lock when sending this
            if ack > 0:
                m = Message()
                m.add_byte(cMSG_CHANNEL_WINDOW_ADJUST)
                m.add_int(self.remote_chanid)
                m.add_int(ack)
                self.transport._send_user_message(m)

        return out

class BCTransport( Transport ):
    def set_limit( self, limit ):
        self.limit = limit

    def open_channel(
        self,
        kind,
        dest_addr=None,
        src_addr=None,
        window_size=None,
        max_packet_size=None,
        timeout=None,
    ):
        """
        Request a new channel to the server. `Channels <.Channel>` are
        socket-like objects used for the actual transfer of data across the
        session. You may only request a channel after negotiating encryption
        (using `connect` or `start_client`) and authenticating.

        .. note:: Modifying the the window and packet sizes might have adverse
            effects on the channel created. The default values are the same
            as in the OpenSSH code base and have been battle tested.

        :param str kind:
            the kind of channel requested (usually ``"session"``,
            ``"forwarded-tcpip"``, ``"direct-tcpip"``, or ``"x11"``)
        :param tuple dest_addr:
            the destination address (address + port tuple) of this port
            forwarding, if ``kind`` is ``"forwarded-tcpip"`` or
            ``"direct-tcpip"`` (ignored for other channel types)
        :param src_addr: the source address of this port forwarding, if
            ``kind`` is ``"forwarded-tcpip"``, ``"direct-tcpip"``, or ``"x11"``
        :param int window_size:
            optional window size for this session.
        :param int max_packet_size:
            optional max packet size for this session.
        :param float timeout:
            optional timeout opening a channel, default 3600s (1h)
        :param float limit:
            optional Limits the used bandwidth, specified in Mbit/s.

        :return: a new `.Channel` on success

        :raises:
            `.SSHException` -- if the request is rejected, the session ends
            prematurely or there is a timeout openning a channel

        .. versionchanged:: 1.15
            Added the ``window_size`` and ``max_packet_size`` arguments.
        """
        if not self.active:
            raise SSHException("SSH session not active")
        timeout = 3600 if timeout is None else timeout
        self.lock.acquire()
        try:
            window_size = self._sanitize_window_size(window_size)
            max_packet_size = self._sanitize_packet_size(max_packet_size)
            chanid = self._next_channel()
            m = Message()
            m.add_byte(cMSG_CHANNEL_OPEN)
            m.add_string(kind)
            m.add_int(chanid)
            m.add_int(window_size)
            m.add_int(max_packet_size)
            if (kind == "forwarded-tcpip") or (kind == "direct-tcpip"):
                m.add_string(dest_addr[0])
                m.add_int(dest_addr[1])
                m.add_string(src_addr[0])
                m.add_int(src_addr[1])
            elif kind == "x11":
                m.add_string(src_addr[0])
                m.add_int(src_addr[1])
            chan = BCChannel(chanid)
            if self.limit is not None:
                chan.set_limit( limit=self.limit ) 
            self._channels.put(chanid, chan)
            self.channel_events[chanid] = event = threading.Event()
            self.channels_seen[chanid] = True
            chan._set_transport(self)
            chan._set_window(window_size, max_packet_size)
        finally:
            self.lock.release()
        self._send_user_message(m)
        start_ts = time.time()
        while True:
            event.wait(0.1)
            if not self.active:
                e = self.get_exception()
                if e is None:
                    e = SSHException("Unable to open channel.")
                raise e
            if event.is_set():
                break
            elif start_ts + timeout < time.time():
                raise SSHException("Timeout opening channel.")
        chan = self._channels.get(chanid)
        if chan is not None:
            return chan
        e = self.get_exception()
        if e is None:
            e = SSHException("Unable to open channel.")
        raise e


class BCSSHClient( SSHClient ):

    def connect(
        self,
        hostname,
        port=SSH_PORT,
        username=None,
        password=None,
        pkey=None,
        key_filename=None,
        timeout=None,
        allow_agent=True,
        look_for_keys=True,
        compress=False,
        sock=None,
        gss_auth=False,
        gss_kex=False,
        gss_deleg_creds=True,
        gss_host=None,
        banner_timeout=None,
        auth_timeout=None,
        gss_trust_dns=True,
        passphrase=None,
        limit=None,
    ):
        """
        Connect to an SSH server and authenticate to it.  The server's host key
        is checked against the system host keys (see `load_system_host_keys`)
        and any local host keys (`load_host_keys`).  If the server's hostname
        is not found in either set of host keys, the missing host key policy
        is used (see `set_missing_host_key_policy`).  The default policy is
        to reject the key and raise an `.SSHException`.

        Authentication is attempted in the following order of priority:

            - The ``pkey`` or ``key_filename`` passed in (if any)

              - ``key_filename`` may contain OpenSSH public certificate paths
                as well as regular private-key paths; when files ending in
                ``-cert.pub`` are found, they are assumed to match a private
                key, and both components will be loaded. (The private key
                itself does *not* need to be listed in ``key_filename`` for
                this to occur - *just* the certificate.)

            - Any key we can find through an SSH agent
            - Any "id_rsa", "id_dsa" or "id_ecdsa" key discoverable in
              ``~/.ssh/``

              - When OpenSSH-style public certificates exist that match an
                existing such private key (so e.g. one has ``id_rsa`` and
                ``id_rsa-cert.pub``) the certificate will be loaded alongside
                the private key and used for authentication.

            - Plain username/password auth, if a password was given

        If a private key requires a password to unlock it, and a password is
        passed in, that password will be used to attempt to unlock the key.

        :param str hostname: the server to connect to
        :param int port: the server port to connect to
        :param str username:
            the username to authenticate as (defaults to the current local
            username)
        :param str password:
            Used for password authentication; is also used for private key
            decryption if ``passphrase`` is not given.
        :param str passphrase:
            Used for decrypting private keys.
        :param .PKey pkey: an optional private key to use for authentication
        :param str key_filename:
            the filename, or list of filenames, of optional private key(s)
            and/or certs to try for authentication
        :param float timeout:
            an optional timeout (in seconds) for the TCP connect
        :param bool allow_agent:
            set to False to disable connecting to the SSH agent
        :param bool look_for_keys:
            set to False to disable searching for discoverable private key
            files in ``~/.ssh/``
        :param bool compress: set to True to turn on compression
        :param socket sock:
            an open socket or socket-like object (such as a `.Channel`) to use
            for communication to the target host
        :param bool gss_auth:
            ``True`` if you want to use GSS-API authentication
        :param bool gss_kex:
            Perform GSS-API Key Exchange and user authentication
        :param bool gss_deleg_creds: Delegate GSS-API client credentials or not
        :param str gss_host:
            The targets name in the kerberos database. default: hostname
        :param bool gss_trust_dns:
            Indicates whether or not the DNS is trusted to securely
            canonicalize the name of the host being connected to (default
            ``True``).
        :param float banner_timeout: an optional timeout (in seconds) to wait
            for the SSH banner to be presented.
        :param float auth_timeout: an optional timeout (in seconds) to wait for
            an authentication response.
        :param float limit:
            optional Limits the used bandwidth, specified in Mbit/s.

        :raises:
            `.BadHostKeyException` -- if the server's host key could not be
            verified
        :raises: `.AuthenticationException` -- if authentication failed
        :raises:
            `.SSHException` -- if there was any other error connecting or
            establishing an SSH session
        :raises socket.error: if a socket error occurred while connecting

        .. versionchanged:: 1.15
            Added the ``banner_timeout``, ``gss_auth``, ``gss_kex``,
            ``gss_deleg_creds`` and ``gss_host`` arguments.
        .. versionchanged:: 2.3
            Added the ``gss_trust_dns`` argument.
        .. versionchanged:: 2.4
            Added the ``passphrase`` argument.
        """
        if not sock:
            errors = {}
            # Try multiple possible address families (e.g. IPv4 vs IPv6)
            to_try = list(self._families_and_addresses(hostname, port))
            for af, addr in to_try:
                try:
                    sock = socket.socket(af, socket.SOCK_STREAM)
                    if timeout is not None:
                        try:
                            sock.settimeout(timeout)
                        except:
                            pass
                    retry_on_signal(lambda: sock.connect(addr))
                    # Break out of the loop on success
                    break
                except socket.error as e:
                    # Raise anything that isn't a straight up connection error
                    # (such as a resolution error)
                    if e.errno not in (ECONNREFUSED, EHOSTUNREACH):
                        raise
                    # Capture anything else so we know how the run looks once
                    # iteration is complete. Retain info about which attempt
                    # this was.
                    errors[addr] = e

            # Make sure we explode usefully if no address family attempts
            # succeeded. We've no way of knowing which error is the "right"
            # one, so we construct a hybrid exception containing all the real
            # ones, of a subclass that client code should still be watching for
            # (socket.error)
            if len(errors) == len(to_try):
                raise NoValidConnectionsError(errors)

        t = self._transport = BCTransport(
            sock, gss_kex=gss_kex, gss_deleg_creds=gss_deleg_creds
        )
        if limit is not None:
            t.set_limit( limit=limit )
        t.use_compression(compress=compress)
        t.set_gss_host(
            # t.hostname may be None, but GSS-API requires a target name.
            # Therefore use hostname as fallback.
            gss_host=gss_host or hostname,
            trust_dns=gss_trust_dns,
            gssapi_requested=gss_auth or gss_kex,
        )
        if self._log_channel is not None:
            t.set_log_channel(self._log_channel)
        if banner_timeout is not None:
            t.banner_timeout = banner_timeout
        if auth_timeout is not None:
            t.auth_timeout = auth_timeout

        if port == SSH_PORT:
            server_hostkey_name = hostname
        else:
            server_hostkey_name = "[{}]:{}".format(hostname, port)
        our_server_keys = None

        our_server_keys = self._system_host_keys.get(server_hostkey_name)
        if our_server_keys is None:
            our_server_keys = self._host_keys.get(server_hostkey_name)
        if our_server_keys is not None:
            keytype = our_server_keys.keys()[0]
            sec_opts = t.get_security_options()
            other_types = [x for x in sec_opts.key_types if x != keytype]
            sec_opts.key_types = [keytype] + other_types

        t.start_client(timeout=timeout)

        # If GSS-API Key Exchange is performed we are not required to check the
        # host key, because the host is authenticated via GSS-API / SSPI as
        # well as our client.
        if not self._transport.gss_kex_used:
            server_key = t.get_remote_server_key()
            if our_server_keys is None:
                # will raise exception if the key is rejected
                self._policy.missing_host_key(
                    self, server_hostkey_name, server_key
                )
            else:
                our_key = our_server_keys.get(server_key.get_name())
                if our_key != server_key:
                    if our_key is None:
                        our_key = list(our_server_keys.values())[0]
                    raise BadHostKeyException(hostname, server_key, our_key)

        if username is None:
            username = getpass.getuser()

        if key_filename is None:
            key_filenames = []
        elif isinstance(key_filename, string_types):
            key_filenames = [key_filename]
        else:
            key_filenames = key_filename

        self._auth(
            username,
            password,
            pkey,
            key_filenames,
            allow_agent,
            look_for_keys,
            gss_auth,
            gss_kex,
            gss_deleg_creds,
            t.gss_host,
            passphrase,
        )


