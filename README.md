# idatojson
- IDAPython 기반으로 함수 이름 및 offset을 json으로 출력해주는 스크립트
- [tracer.py](https://github.com/5hale/tracer)의 `--json` 옵션에 사용 가능

## 종속성(dependencies)
- json
- IDA에 Python 플러그인 필요

## idatojson_ida.py
- IDA GUI에서 사용 가능한 스크립트
- idc 명령줄을 python으로 변경 후 파일 실행
- 추출할 섹션 문자열을 소스코드의 sections에서 수정 가능

#### Usage
```Python
exec(open("C:\\idatojson_ida.py").read())
```

## idatojson_cmd.py
- 해당 스크립트는 `idat.exe` 또는 `idat64.exe` 파일 위치를 환경변수 저장 필요
- 추출할 섹션 문자열을 받으며 `::`로 구분
- `idat64.exe` 사용 시 `-S` 옵션뒤에 띄어쓰기 있으면 오류남

#### Usage
```powershell
idat64 -S"C:\idatojson_cmd.py text::extern C:\\" "C:\test.so"
```

