import os
from dotenv import load_dotenv

load_dotenv()  

MULTIPLIER = int(os.getenv("MULTIPLIER", 5**5))
INCREASE = int(os.getenv("INCREASE", 34))
COMPARISON_MODULE = int(os.getenv("COMPARISON_MODULE", 2**13 - 1))
INITIAL_NUMBER = int(os.getenv("INITIAL_NUMBER", 16))
RC5_WORD_SIZE = int(os.getenv("RC5_WORD_SIZE", 16))
RC5_ROUNDS =  int(os.getenv("RC5_ROUNDS", 20))
KEY_SIZE = int(os.getenv("KEY_SIZE", 16))
STREAM_CHUNK_SIZE = int(os.getenv("STREAM_CHUNK_SIZE", 1024 * 1024))