import sys
import re
import string

def testLog(file):
	pfile = open(file, 'r')	
	
	content = pfile.readlines()
	
	for x in range (0, len(content)-1, 2):
		pattern = content[x+1][:-1]
		tokens = string.split(pattern, ",")
		for token in tokens:
			if not re.search(token, content[x]):
				print "ASSERT ERROR: " + token + " IS NOT IN " + content[x]
				sys.exit()

	
	print "PASS OK!"

if __name__ == '__main__':
	testLog(sys.argv[1])

	    
