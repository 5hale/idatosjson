# Command Example
	# exec(open("C:\\idatojson_ida.py").read())
import idautils
import json
import sys, os
import re

# 추출할 섹션 넣기
sections = ["text","il2cpp"]

# 모듈 이름 가져오기
module = ida_nalt.get_root_filename()
file_name = module+".json"

# json 헤더 설정
with open(file_name, "w") as f: f.write("{\n"+"\"Module\" : \""+module+"\",\n")

# Segments() : 모든 세그먼트의 시작위치 출력
for seg in Segments(): 
	try:
		# 시작위치를 기반으로 세그먼트(섹션) 이름 중 .text와 il2cpp의 주소만 걸러내기
		for section in sections:
			seg_name = idc.SegName(seg)		# 세그먼트 이름
			seg_start = idc.SegStart(seg)	# 세그먼트 시작 주소
			seg_end = idc.SegEnd(seg)  		# 세그먼트 마지막 주소
			if(section in seg_name):
				# 세그먼트 이름, 시작주소, 끝주소 출력
				print(seg_name, seg_start, seg_end)
				json_object=[]
				# 시작위치 기반으로 해당 세그먼트의 모든 함수의 주소 가져오기
				for i, func in enumerate(idautils.Functions(seg_start,seg_end)):
					func_name = idc.GetFunctionName(func) 	# 해당 함수의 이름 가져오기
					func = re.sub("^10*","","%x" %func,1)	# 1000.*으로 시작하는 주소 앞부분 제거
					offset = "0x%s" %func					# 주소를 0x00 형태로 변형
				
					json_object.append({
						"Name": func_name,
					    "Address": offset					    
					})
				
				with open(file_name, "a") as f:
					f.write("\""+seg_name+"\""+":")
					json.dump(json_object,f,indent=2)
					f.write(",")
			else: pass
	except Exception as e: print(e)

# json 푸터 설정
with open(file_name, "r+") as f: f.seek(-1,2), f.write("}")