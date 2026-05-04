import re
import sys

print(re.sub(r"[\-\./\(\)]", "_", sys.argv[1]), end="")
