# -*- encoding: UTF-8 -*-
import fileinput                         
                                        
for line in fileinput.input(inplace=True): 
	line = line.rstrip()                
	num = fileinput.lineno()          
	print '%-50s joel %50i;' % (line, num)    
 
