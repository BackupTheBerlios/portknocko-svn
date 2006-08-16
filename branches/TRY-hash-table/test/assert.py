import sys
import re
from string import split
from string import strip

def failure(token, line, msg):
	print "ASSERT ERROR: " + token + " " + msg  + " " + line
	sys.exit()


def testLog(file):
	pfile = open(file, 'r')	
	
	content = pfile.readlines()
	
	for x in range (0, len(content)-1, 2):
		pattern = content[x+1].strip("\n")
		tokens = pattern.split(",")
		for token in tokens:
			if token[0] == "!":
				if re.search(token[1:], content[x]):
					failure(token[1:], content[x], "IS IN")
			else:
				if not re.search(token, content[x]):
					failure(token, content[x], "IS NOT IN")

	
	print "PASS OK!"

if __name__ == '__main__':
	testLog(sys.argv[1])

	    
