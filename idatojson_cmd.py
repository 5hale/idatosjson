# [caution] If you write in Korean, an error remains even in the comments.

# Command Example
	# idat64 -S"C:\idatojson_cmd.py text::extern C:\\" "C:\test.so"
import idautils
import json
import sys, os

def main(sections,file_path):
	# Get module name
	module = ida_nalt.get_root_filename()
	file_name = module+".json"
	file_path = file_path + file_name

	# Create File and Set Header		
	with open(file_path, "w") as f: f.write("{\n"+"\"Module\" : \""+module+"\",\n")
	idc.auto_wait()

	# Function and Offset extractor
	# Segments() : Get all segment address
	for seg in Segments(): 
		try:
			# user input sections
			for section in sections:
				seg_name = idc.SegName(seg)		# Segment Name : .text, __text, data, rodata, cstring ...
				seg_start = idc.SegStart(seg)	# Segment Start Address
				seg_end = idc.SegEnd(seg)  		# Segment

				if(section in seg_name):
					json_object=[]
					
					# Get Function and Offset for user input section
					for i, func in enumerate(idautils.Functions(seg_start,seg_end)):
						func_name = idc.GetFunctionName(func) 	# Get Function Name
						func = re.sub("^10*","","%x" %func,1)	# if Start for 1000.*, replace to nothing
						offset = "0x%x" %func					# Change form to 0x00 for Address
					
						# Create json object
						json_object.append({
							"Name": func_name,
						    "Address": offset					    
						})
					
					# Write file
					with open(file_path, "a") as f:
						f.write("\""+seg_name+"\""+":")
						json.dump(json_object,f,indent=2)
						f.write(",")
				else: pass
		except Exception as e: 
			# if come error, check "error.txt"
			with open("error.txt", "a") as f: f.write(e)

	# Set Footer
	with open(file_path, "r+") as f: f.seek(-1,2), f.write("}")

if __name__ == '__main__':
    if len(idc.ARGV) != 3:
    	pass
        print("IDAPython JSON script needs \"Section\" and File path")
        print('Usage: ' + idc.ARGV[0] + ' [sections] [file_path]')
    try:
    	sections = []
    	args = idc.ARGV[1].split('::')				# divide user input sections for "::"
    	for i in args: sections.append(i)			# Set sections on list
    	file_path = idc.ARGV[2]						# Set save file path
    except Exception as e:
    	# if come error, check "error.txt"
    	with open("error.txt", "a") as f: f.write(e)
    	idc.qexit(0)
    main(sections,file_path)
    idc.qexit(0)

    