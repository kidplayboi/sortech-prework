# 핸드오프 — 집에서 이어서 할 것 (2026-07-31 18:00 기준)

> 회사에서 여기까지 했고, 집에서 이어서 하면 된다.
> 순서대로 하면 되고, 각 단계에 "왜"와 "확인 방법"을 같이 적었다.

## 지금 상태 한 줄

**코드·문서는 끝났다. 남은 건 ① 원격에 푸시 ② 녹화 ③ 메일 발송 — 세 개뿐이다.**

| 항목 | 상태 |
|---|---|
| 코드 (L1~L5) | ✅ 동결. 새 기능 추가 없음 |
| 테스트 | ✅ full 101개 OK · 클린 설치 98개 OK(skipped=1) |
| S1·S2 문서 | ✅ docx/pdf 생성 완료 (`~/Downloads/sortech-제출/`) |
| git 이력 민감정보 | ✅ **로컬은 정리 끝** · 🔴 **원격 푸시 미완** ← 1번 |
| 실행 화면 녹화 | 🔴 미완 ← 2번 |
| 메일 발송 | 🔴 미완 ← 3번 |

---

## 0️⃣ 집에서 이어서 작업하려면 — **푸시가 먼저다**

⚠️**지금 원격은 옛 이력이다.** 푸시하지 않고 집에서 `git clone` 하면 **오늘 작업 49커밋이
통째로 없는 상태**를 받는다. 순서는 둘 중 하나:

**방법 A (권장) — 이 PC에서 푸시하고, 집에서 clone**
```powershell
# 이 PC에서 (1번 참고)
git push --force origin main
# 집에서
git clone https://github.com/kidplayboi/sortech-prework.git
```

**방법 B — 푸시를 못 하겠으면 번들을 들고 간다**

`C:\Users\test\Downloads\sortech-제출\sortech-prework-현재상태.bundle` (17.6 MB)
— 이 파일 하나에 커밋 49개 전체가 들어 있다(복원 검증 완료).

```powershell
# 집에서 (USB나 클라우드로 옮긴 뒤)
git clone sortech-prework-현재상태.bundle sortech-prework
cd sortech-prework
git remote set-url origin https://github.com/kidplayboi/sortech-prework.git
```

집에서도 `.mask-terms.local`은 없다(git 무시). `tools/extract_log.py`를 쓸 일이 없으면
상관없고, 쓸 거면 이 PC에서 그 파일도 같이 옮겨야 한다.

## 1️⃣ 먼저: 원격에 푸시 (형이 직접 실행)

git 이력에 남아 있던 **클라이언트명·봇ID를 로컬에서 전부 치환**했다(감사 결과 0건).
커밋 47개는 그대로 보존됐고 순서·메시지도 유지된다. 다만 **내용이 바뀌었으니 커밋
해시가 전부 새로 생겼다** — 그래서 force push가 필요하고, 그건 에이전트가 실행할 수
없게 막혀 있다(하네스 가드).

```powershell
cd C:\Users\test\sortech-prework
git push --force origin main
```

**확인**: 아래 두 값이 같아야 한다.
```powershell
git rev-parse HEAD
git ls-remote origin main
```

- 현재 로컬 HEAD = `f04e3b2` (커밋 47개)
- 푸시 전 원격 = `b914733` (옛 이력)

**되돌리려면**: 백업이 `C:\Users\test\Downloads\sortech-백업-이력재작성전\`에 있다.
`sortech-prework-full.bundle` 하나로 통째로 복원된다(복원 검증까지 마쳤다).

> ⚠️GitHub는 force push 후에도 옛 객체를 한동안 들고 있을 수 있다. 완전 제거가
> 필요하면 GitHub 지원에 gc 요청을 해야 한다. 지금 노출량은 커밋 2개·10줄이었다.

---

## 2️⃣ 녹화 (4~6분, 무편집)

### 촬영 전 준비 — 이게 제일 중요하다

**재부팅하거나, 최소한 메신저·브라우저·다른 작업 창을 전부 닫는다.**

리허설 때 실제로 다른 프로젝트 작업 창과 메신저가 그대로 녹화됐다. 녹화는 화면의
사각형을 찍는 것이라 그 자리에 있는 게 다 찍힌다. 그대로 제출했으면 공개 제출물에
무관한 정보가 들어갔다.

- [ ] 재부팅 (또는 다른 창 전부 닫기)
- [ ] 알림 끄기 (집중 지원 켜기)
- [ ] 데모용 터미널 **하나만** 띄우기, 최대화

### 실행

새 터미널 창에서 한 줄:

```powershell
cd C:\Users\test\sortech-prework
powershell -NoProfile -ExecutionPolicy Bypass -File docs\demo\run-and-record.ps1
```

**그다음 그 창을 건드리지 않는다.** 대본·타이밍·읽을 시간이 전부 스크립트에 있다.
스크립트가 자기 창이 최상위일 때만 녹화하고, 아니면 중단한다(바탕화면 전체로
대체하는 경로는 아예 없다).

결과물은 **바로 제출 폴더에 떨어진다**: `~/Downloads/sortech-제출/실행화면-녹화.mp4`

### 촬영 후 — 반드시

- [ ] **영상을 직접 재생해서 눈으로 확인.** 다른 창이 찍히지 않았는지. 이 단계는
      건너뛰지 않는다 — 리허설 사고를 잡은 게 이 단계였다.
- [ ] 길이가 4~6분인지 (현재 대본은 약 3분 — 아래 참고)

### 대본 내용 (`docs/demo/demo.ps1`)

현재 6구간 약 3분 구성이다. 4~6분으로 늘리려면 각 구간의 `Start-Sleep`을 키우거나
설명 카드를 추가하면 된다. 담을 것은 이 순서가 좋다:

1. **과제 의도와 내 해석** — 무엇을 자동화했고 왜 필요한가
2. **실제 동작 한 번** — `watcher status` 5층 결과
3. **AI가 틀리거나 한계를 보인 장면 + 내 판단** ← 이게 핵심 점수
4. **L1~L3 필수 / L4~L5 확장 구분** — 핵심 제품과 선택 확장을 명확히
5. **테스트 101개와 재현 방법**
6. **한계 한 문장**

> 전 기능을 자랑하는 영상이 아니라 **"AI가 만들었지만 내가 검증하고 결정했다"**를
> 증명하는 영상으로 간다.

---

## 3️⃣ 메일 발송

초안: `~/Downloads/sortech-제출/메일-초안.md`

- 받는 사람: `juran03@sortech.co.kr`
- 첨부 3개: `S1-AI활용기록.pdf` · `S2-회고.pdf` · `실행화면-녹화.mp4`
- **이름·연락처 자리가 비어 있다** — 채울 것
- 근무지 문구는 이미 반영됨 (AI Native 경력직 / 경기지사 성남 분당 수내동 조건)

발송 전 체크리스트가 초안 맨 아래에 있다.

---

## 문서를 고쳐야 할 때

마크다운 원본을 고치고 빌더를 돌리면 docx·pdf·제출폴더가 한 번에 갱신된다.

```powershell
cd C:\Users\test\sortech-prework
python tools\build_submission.py
```

- 원본: `docs/제출물/S1-AI활용기록.md` · `S2-회고.md` · `메일-초안.md`
- 출력: `~/Downloads/sortech-제출/`

---

## 알아둘 것

- **`.mask-terms.local`** — 마스킹용 식별어 목록. git이 무시하므로 이 PC에만 있다.
  다른 PC에서 `tools/extract_log.py`를 돌리려면 이 파일을 옮겨야 한다(없으면 감사가 경고).
- **첫 `status`가 🟠인 건 정상** — 기본 설치엔 브라우저가 없어 L4가 "검증 불가"로
  나온다. 사이트 문제가 아니라 우리가 확인을 못 한 것이고, README에 이유와 해제법이 있다.
- **제출 폴더는 레포 밖**(`~/Downloads/sortech-제출/`)이다. 대용량 바이너리를 레포에
  쌓지 않고, 첨부할 때 바로 찾는 자리에 두려는 것.

## 남은 판단 (형)

- 녹화 대본을 3분 → 4~6분으로 늘릴지, 지금 길이로 갈지
- S1이 11쪽이다. 반복 서술을 줄일지 그대로 갈지
- GitHub Actions(클린 core 테스트) 추가 여부 — 지금은 없다
