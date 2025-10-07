import os
from dotenv import load_dotenv

load_dotenv()  

MULTIPLIER = int(os.getenv("MULTIPLIER", 5**5))
INCREASE = int(os.getenv("INCREASE", 34))
COMPARISON_MODULE = int(os.getenv("COMPARISON_MODULE", 2**13 - 1))
INITIAL_NUMBER = int(os.getenv("INITIAL_NUMBER", 16))