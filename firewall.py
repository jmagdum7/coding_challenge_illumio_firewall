# Uses pandas library
import pandas as pd

class Firewall:
	def __init__(self, path):
		# Initialization
		self.flag = True
		# Stores rules in a data frame
		self.rules = pd.read_csv(path, header=None)
	
	# Method for cleaning and checking valid test cases
	def preprocess(self, x):
		y = [a.strip() for a in x.split(',')]
		y = [a.strip('\"') for a in y]
		
		# if direction is not one of these, set the flag to false -  No more processing required
		if y[0] != "inbound" and y[0] != "outbound":
			print("Invalid direction")
			self.flag = False
		
		# if protocol is not one of these, set the flag to false -  No more processing required
		if y[1] != "tcp" and y[1] != "udp":
			print("Invalid Protocol - ", end="")
			self.flag = False
		else:
			self.flag = True
		return y
	
	# Method to validate test cases on the basis of the given set of rules
	def validate(self, dir, protocol, port, ip, fields):
		count = 0
		
		for x in fields:
			df = self.rules.iloc[[x]]
		for index, row in df.iterrows():
			# Check if all the four fields match, if it matches, increase count by 1
			# The approach behind this is that if all the fields match, count will be equal to 4
			
			if row[0] == str(dir):
				count += 1
			if row[1] == str(protocol):
				count += 1
			
			if row[2] == str(port):
				count += 1
			# Check if port in the given range
			elif '-' in row[2]:
				x = row[2].split('-')
				if int(port) in range(int(x[0]), int(x[1])):
					count += 1
			
			if row[3] == str(ip):
				count += 1
			# Check if ip in the given range
			elif '-' in row[3]:
				ip_part = ip.split('.')[2:]
				ip_numbers = int(''.join(map(str, ip_part)))
				parts = []
				
				t = row[3].split('-')
				for q in t:
					p = q.split('.')[2:]
					parts.append(int(''.join(map(str, p))))
				
				if ip_numbers in range(parts[0], parts[1]):
					count += 1
			
			return count
	
	def accept_packet(self, dir, protocol, port, ip):
		if self.flag == True:
			port_check = self.rules.loc[self.rules[2] == str(port)]
			ip_check = self.rules.loc[self.rules[3] == str(ip)]
			fields = set(ip_check.index.values).union(set(port_check.index.values))
			
			# If one of the two matches with the rules, check for other parameters
			if len(fields) >= 1:
				count = self.validate(dir, protocol, port, ip, fields)
			
			else:
				# Check for matching Direction or protocol
				direction_check = self.rules.loc[self.rules[0] == str(dir)]
				protocol_check = self.rules.loc[self.rules[1] == str(protocol)]
				fields = set(direction_check.index.values).union(set(protocol_check.index.values))
				
				# If one of the two matches, check for other parameters
				if len(fields) >= 1:
					count = self.validate(dir, protocol, port, ip, fields)
			
			# For case to be accepted, count must be 4, else, do not accept and return False
			if count == 4:
				return True
			else:
				return False
		else:
			return False
