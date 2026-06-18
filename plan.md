# Fuck Grabber Up 기획서

감염 의심 시 피해 확산을 멈추고, 흔적을 수집하고, 계정 탈취 리스크를 줄이는 IR 보조 도구.
가장 중요한 포인트는

```
즉시 격리 + 흔적 수집 + 지속성 제거 후보 제시 + 계정 조치 체크리스트
```

## MVP

### 1. 네트워크 격리

일단 가장 중요한 건 더이상의 유출을 막는 것.

아래는 Windows Defender Firewall에서 특정 프로그램의 out-bound 통신을 차단하는 PowerShell 명령어다.

```
New-NetFirewallRule -DisplayName "StealerGuard Block Outbound" -Direction Outbound -Action Block -Program "C:\path\suspect.exe"
```

### 2. 자동 실행 지점 스캔

대부분의 경우 단순 시스템 종료로 감염을 막을 수 없음.

최소 아래 확인 대상을 모두 체크해봐야 함.

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
Startup Folder
Scheduled Tasks
Services
Winlogon/Userinit/Shell
Image File Execution Options
AppInit_DLLs
Browser extension directories
```

### 3. 예약 작업 검사

InfoStealer가 schtasks 사용해서 재실행 걸어두는 경우도 있음.

때문에 그 리스트를 확인해야 함.

```
schtasks /query /v /fo CSV
```

탐지 휴리스틱은 다음과 같음.

```
- AppData, Temp, Downloads, ProgramData에서 실행
- powershell.exe, wscript.exe, cscript.exe, mshta.exe, rundll32.exe 호출
- 무작위 이름
- 숨김 작업
- 최근 생성됨
```

### 4. Windows Defender 로그 수집

Defender Operational 로그는 공식적으로 아래에서 확인 가능함.

```
Applications and Services Logs
→ Microsoft
→ Windows
→ Windows Defender
→ Operational
```

MVP 단계에선 PowerShell 명령으로 확인하면 될듯.

```
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
  Select-Object TimeCreated, Id, ProviderName, Message
```

특히 아래 이벤트 꼭 확인해볼 것.

```
1116: Malware detected
1117: Malware action taken
5007: Defender 설정 변경
```

### 5. 브라우저/토큰 탈취 피해 완화

토큰을 복구한다거나, 읽어오는 기능은 만들면 안 됨. 악성코드랑 경계가 겹치기 때문.

대신 사용자가 무효화하도록 유도해야 함.

```
- 모든 브라우저 완전 종료
- 브라우저 세션/쿠키 삭제 안내
- Google/Microsoft/Discord/GitHub 등 로그인된 세션 로그아웃 페이지 열기
- 비밀번호 변경
- 2FA 재등록 확인
- 패스키 사용 권장
```

> 요즘은 2차인증 이런 것도 다 뚫려서 2FA 재등록도 확인해야 함.

### 6. 의심 파일 점수화

아무 동의 없이 바로 삭제를 자동화하면 위험하기 때문에 처음엔 점수화 + 격리 후보 산출이 좋음.

```
+30 AppData/Temp/Downloads에서 실행
+20 자동 실행 등록됨
+20 서명 없음
+15 생성 시간이 최근 24시간 이내
+15 이름이 정상 프로세스 위장: svchost, chrome, discord, update 등
+15 Defender 탐지 로그와 경로 일치
+10 네트워크 연결 있음
+10 압축 해제 직후 생성됨
```

행동 팁은 아래와 같다.

```
0~30: 참고
31~60: 의심
61~80: 강한 의심
81+: 격리 권장
```

## 구현 순위

### 1. Read-only 스캐너

```
Run/RunOnce
Startup Folder
Scheduled Tasks
Defender 로그
JSON 리포트
```

### 2. 의심 점수화

```
경로, 서명 여부, 생성 시간, 자동 실행 여부
```

### 3. 대응 모드

```
의심 프로세스 종료
방화벽 outbound 차단
파일 이름 변경 격리
자동 실행 항목 비활성화
```

### 4. 피해 완화 도움

```
세션 로그아웃 링크 모음
브라우저 종료
쿠키 삭제 안내
비밀번호/2FA/패스키 체크리스트
```

### 5. 고도화

```
Autoruns CLI 결과 파싱
서비스/Winlogon/IFEO 검사
Event Log API 직접 사용
YARA 룰 연동
```

