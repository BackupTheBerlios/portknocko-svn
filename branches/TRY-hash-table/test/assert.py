import sys
import re

def testLog(file):
	pfile = open(file, 'r')	
	
	content = pfile.readlines()
	
	for x in range (0, len(content)-1, 2):
		pattern = content[x+1][:-1]
		if not re.search(pattern, content[x]):
			print "ASSERT ERROR: " + pattern + " IS NOT IN " + content[x]
			sys.exit()

	
	print "PASS OK!"

if __name__ == '__main__':
	testLog(sys.argv[1])

	    
