import time
import threading

class Snowflake:
    def __init__(self):
        self.sequence = 0
        self.epoch = 1609459200  # Unix-Zeitstempel: 1. Januar 2021, 00:00:00 UTC
        self.machine_id = 0
        self.lock = threading.Lock()

    def generate_id(self):
        with self.lock:
            timestamp = int(time.time()) - self.epoch
            snowflake_id = (timestamp << 22) | (self.machine_id << 12) | self.sequence
            self.sequence = (self.sequence + 1) & 4095  # 12 bits für die Sequenznummer (0-4095)
        return snowflake_id