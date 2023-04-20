from nacl.signing import SigningKey
import hashlib
import time
from termcolor import colored
from multiprocessing import Process, Queue
import os


class Account:

    def __init__(self) -> None:
        self.signing_key = SigningKey.generate()

    def address(self) -> str:
        return self.auth_key()[-1:]

    def auth_key(self) -> str:
        hasher = hashlib.sha3_256()
        hasher.update(self.signing_key.verify_key.encode() + b"\x00")
        return hasher.hexdigest()

    def priv_key(self) -> str:
        return self.signing_key._seed.hex()


def gen_addresses(prefix: str, suffix: str, result_queue: Queue) -> None:
    while True:
        temp = Account()
        address = temp.address()
        if address.startswith(prefix) and address.endswith(suffix):
            print(f"Address: 0x{address}")
            print(colored(f"Private key: {temp.priv_key()}", 'green'))
            result_queue.put(temp.priv_key())
            return


if __name__ == "__main__":
    prefix = "1337"   # <------------
    suffix = "1337"   # <------------
    start_time = time.time()
    print(colored(f"Mining vanity address with a prefix starting with {prefix} and ending with {suffix}...", 'yellow'))

    result_queue = Queue()

    num_processes = 5 # change 5 to  os.cpu_count()  to use all cores
    processes = [
        Process(target=gen_addresses, args=(prefix, suffix, result_queue))
        for _ in range(num_processes)
    ]

    for p in processes:
        p.start()

    private_key = result_queue.get()

    for p in processes:
        p.terminate()

    print(colored(f"Address found in {round(time.time()-start_time, 2)} seconds", 'blue'))
