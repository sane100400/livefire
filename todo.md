# TODO

## Discord 공지

[공지] A&D 채점 및 가용성 체크 관련 안내  @here

A&D에서는 단순히 공격 벡터를 막기 위해 기능을 삭제하거나 엔드포인트를 없애는 식의 방어는 서비스 가용성을 해친 것으로 판단될 수 있습니다.

채점 기준은 아래처럼 이해하면 됩니다.

공격 성공 / 방어 실패
상대 사이트의 가용성을 해치지 않으면서 제출한 PoC가 유효하게 동작한 경우
공격자는 공격 점수를 획득
방어자는 방어 점수가 차감됨

공격 실패 / 방어 성공
사이트 측에서 해당 공격 PoC를 정상적으로 무력화한 경우
방어 성공 자체로 추가 점수를 주는 방식은 아님
대신 방어 점수가 깎이지 않음

채점은 30분 단위로 진행될 예정입니다. (LiveFire 한 라운드)

채점 순서는 다음과 같습니다.
먼저 사이트 가용성 체크
가용성 통과 시, 제출된 PoC 실행
PoC 공격 성공 여부 확인
결과에 따라 공격/방어 점수 반영

즉, 가용성 체크에서 실패하거나 상대 PoC 공격이 성공하면 방어 점수가 깎입니다. 반대로 공격자는 PoC가 성공했을 때 공격 점수를 받습니다.

오늘 개발 기한 마감 때 까지 본인 팀이 개발한 사이트들을 확인하면서, 의도된 공격 벡터들이 기능 삭제 없이 정상적으로 살아있는지 점검해주세요. 목요일에 해당 공격 벡터 유지 여부를 확인하는 체커 패치를 진행할 예정입니다.

## 가용성 체커 패치 준비

- [x] 현재 코드 흐름 확인: `coordinator/checker.py`가 health -> inject -> retrieve -> basic_function 순서로 서비스 상태를 `OK` / `FAULTY` / `DOWN`으로 기록함.
- [x] 현재 채점 흐름 확인: `start_round()`에서 checker 실행 후 PoC 실행, `end_round()`에서 checker 재실행 후 가용성 점수 반영.
- [x] 현재 PoC 실행 흐름 확인: `poc_runner.py`는 타겟이 `DOWN`이면 PoC를 건너뛰고, `OK`/`FAULTY`면 실행함.
- [ ] 각 팀 개발 사이트의 `vuln_spec.json` 수집.
- [ ] 각 취약점별로 “기능 삭제 여부”를 잡을 수 있는 `checker.basic_function` 또는 별도 벡터 유지 체크 항목 정의.
- [x] `checker.py`의 기존 `basic_function`을 취약점별 전체 AND 조건으로 강화.
- [x] `validate_vulns.py`와 `preflight_check.py`가 취약점별 `basic_function`을 동일하게 검증하는지 확인.
- [x] PoC 제출 제한 추가: 라운드당 `공격팀 -> 타겟팀 -> vuln_id` 기준 queued 2개 유지, 3번째 제출 시 가장 오래된 queued PoC 교체.
- [x] PoC 제출 즉시 실행 제거: 제출은 queued, 라운드 종료 시 batch 실행.
- [x] 라운드 종료 시점의 service image snapshot을 별도 scoring container로 띄워 checker/PoC 실행.
- [x] PoC 성공 점수는 라운드당 `공격팀 -> 타겟팀 -> vuln_id` 기준 1회만 인정.
- [x] 취약점별 PoC timeout override 추가: `poc_timeout_sec`, 기본 상한 120초.
- [ ] 목요일(2026-05-28) 체커 패치 후 전체 팀 대상 `python scripts/gitctf.py admin preflight --repeat 3` 실행.
- [ ] 패치 후 공지: “가용성 실패 또는 PoC 성공 시 방어 점수 차감, PoC 성공 시 공격 점수 지급” 기준 재안내.

## 구현 메모

- 기능 삭제식 방어를 잡으려면 `/health`만으로는 부족함.
- `retrieve`는 flag 저장/회수 확인에 강하고, `basic_function`은 사용자 기능 생존 여부 확인에 적합함.
- `checker.py`는 모든 취약점의 `checker.basic_function`을 실행하도록 패치함. 한 취약점이라도 실패하면 전체 서비스 상태는 `FAULTY`.
- PoC 채점 전 가용성 체크 순서는 이미 `start_round()`에 들어가 있지만, 30분 라운드 종료 시점에도 “checker -> score” 순서가 유지되는지 테스트를 보강하는 것이 좋음.
