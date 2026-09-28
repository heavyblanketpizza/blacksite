# Blacksite

[English](README.md) | [한국어](README.ko.md)

로컬 LLM으로 돌리는 오프라인 장애 분석. 내 것도 아닌 블랙사이트 오두막에서 피할 수 없는 AGI 종말에 대비합니다. 은박지 모자는 별매.

![픽셀 아트로 그린 오프라인 작업 공간](assets/blacksite-homestead.png)

서버의 로그, 설정 파일, 명령 실행 결과를 넣으면 Blacksite가 읽기 전용 도구로 조사하고, 근거 로그 줄과 예상 결과, 되돌리기 절차를 담은 복구 가이드를 씁니다. 서버에서 명령을 실행할 수는 없습니다.

**Ollama, llama.cpp, vLLM**에서 동작하며 로컬 웹 앱과 CLI로 사용합니다.

## 데모

https://github.com/user-attachments/assets/5cdedde4-ccf4-4289-a6a2-121e20cc82ed

59초 데모: 로그인, 근거 검색, 실시간 조사, 인용이 달린 가이드, 서명 검증, 다운로드, 공유, 감사 기록 검증. Qwen 3.8 27B를 llama.cpp에서 로컬 GGUF 가중치와 64k 컨텍스트로 실행하며, 로그와 계정은 합성 자료입니다. 영상은 2배속, 7분간의 조사 구간은 15.5배속이며 화면에 배속을 표시합니다.

## 빠른 시작

Python 3.11 이상, [uv](https://docs.astral.sh/uv/), 실행 중인 [Ollama](https://ollama.com) 서버가 필요합니다. 프로젝트 폴더에서 실행하세요.

```bash
uv sync --extra agent
ollama pull qwen3.8:27b-q4_K_M
ollama create blacksite-qwen3.8 -f demo/Modelfile
uv run blacksite --config demo/blacksite.toml users add admin --admin
uv run blacksite --config demo/blacksite.toml demo --incidents var/demo/incidents --samples --open
```

`users add`는 임시 비밀번호를 한 번만 보여 줍니다. [localhost:8765](http://127.0.0.1:8765)에서 로그인해 새 비밀번호를 정하세요. **인시던트**에서 예제 두 개 중 하나를 골라 **조사 시작**(Investigate)을 누르고, 인용을 클릭하면 원문을 볼 수 있습니다. 화면과 가이드는 한국어와 영어를 지원합니다.

인터넷 없이 쓰려면 의존성과 모델 가중치를 미리 받아 두고, 모델 서버를 로컬에 둔 채 `uv run --offline`으로 실행하세요.

## 내 로그 분석하기

웹 앱에서 파일을 올리거나 CLI를 사용하세요.

```bash
uv run blacksite new var/incidents/INC-1 path/to/app.log --title "API returns 502"
uv run blacksite --config demo/blacksite.toml investigate var/incidents/INC-1
```

에이전트가 자료를 더 요청하면 제안된 명령을 직접 실행하고 결과를 넘기세요.

```bash
uv run blacksite --config demo/blacksite.toml investigate var/incidents/INC-1 --paste output.txt
```

## 설정

`--config`로 TOML 파일을 지정합니다.

| 서버 | 예제 |
| --- | --- |
| Ollama | [demo/blacksite.toml](demo/blacksite.toml) |
| llama.cpp | [demo/llamacpp.toml](demo/llamacpp.toml) |
| vLLM | [demo/vllm.toml](demo/vllm.toml) |

웹 앱의 모델 선택 메뉴에 로컬 모델이 표시됩니다. llama.cpp나 vLLM 실행 방법은 `blacksite serve model --help`에 있습니다. 조사 전에 모델 서버를 점검하세요.

```bash
uv run blacksite --config demo/blacksite.toml check
```

모든 설정은 [blacksite.example.toml](blacksite.example.toml)에 설명되어 있습니다. 운영 문서 검색, 과거 사례 조회, 대응 지침 학습은 기본적으로 꺼져 있고, 새 학습 항목은 사람의 승인이 필요합니다.

## USB로 자료 가져오기

데모는 이동식 드라이브에서 다음 구조를 감지합니다.

```text
<drive>/blacksite/
    api-502/
        incident.txt    # 선택 사항: 제목과 설명
        app.log
        logs.tar.gz
```

사례마다 로컬 샌드박스에 복사해 조사합니다. **드라이브에 저장**하면 원본 옆에 오프라인 HTML 가이드, Markdown 가이드, 파일 매니페스트를 쓰고 샌드박스를 지웁니다. SSD에서는 완전한 삭제를 보장할 수 없으니 민감한 자료에는 전체 디스크 암호화를 쓰세요.

## 접근 관리와 감사 기록

웹 앱은 `127.0.0.1`에서만 열리고, 관리자가 만든 계정만 로그인할 수 있습니다. Blacksite는 `var/`를 혼자 읽을 수 있는 OS 계정 하나로 실행하고, 사용자는 각자의 OS 계정에서 로그인하게 하세요.

- **계정.** 관리자는 **관리 → 멤버** 또는 `blacksite users add 이름`으로 멤버를 추가합니다. 새 멤버는 처음 로그인할 때 임시 비밀번호를 바꿉니다.
- **2단계 로그인**은 등록한 계정을 포함해 모두 꺼져 있으며, 기존 인증 앱 설정과 복구 코드는 보관됩니다. 켜려면 `auth.totp_enabled = true`로 설정하고 재시작하세요. 기존 세션은 종료됩니다. 켜진 뒤에는 관리자는 인증 앱이 필수, 멤버는 선택입니다. 휴대폰을 잃어버리면 복구 코드를, 등록을 초기화하려면 `blacksite users reset-2fa 이름`을 사용하세요.
- **볼 수 있는 범위.** 멤버는 자신이 만들었거나 공유받은 인시던트만 봅니다. 관리자는 모두 보며, 모델, 에이전트 설정, 학습 승인은 관리자만 바꿉니다.
- **감사 기록.** 로그인, 업로드, 조사, 결과 기록, 공유, 내보내기, 관리 변경이 `var/audit.sqlite`에 남습니다. 기록은 해시로 연결되고 키로 서명되어 수정·삭제·순서 변경이 드러납니다. ID, 개수, 해시만 남고 증거, 프롬프트, 비밀번호, 코드는 남지 않습니다. **관리 → 감사 기록 → 체인 검증** 또는 `blacksite audit verify`로 확인하고, **보안 상태**의 앵커 지문을 적어 두세요.
- **가이드 출처.** 가이드마다 실행한 사람, 모든 증거 파일의 SHA-256, 모델과 설정이 서명된 기록으로 남습니다. USB로 내보낼 때 함께 저장되며, 어느 컴퓨터에서나 `blacksite verify <폴더>`로 확인할 수 있습니다.

`var/keys/`는 비공개로 두고 백업하세요. 감사 기록과 가이드가 이 컴퓨터에서 나왔음을 증명하는 키가 들어 있습니다.

## 데이터와 검증

- 색인할 때 인식된 비밀 값을 가리고, 로그 속 의심스러운 지시문을 표시합니다.
- 가이드 검증은 인용된 파일과 줄 번호를 확인하고 위험한 명령을 표시합니다. 실행 전에 가이드와 경고를 검토하세요.
- 추론 요청은 설정한 모델 서버로 가며, 임베딩과 재순위화를 켜면 해당 서버로도 갑니다.
- 실행 데이터는 `var/`에 저장되며 Git에서 제외됩니다. `tests/fixtures/`는 합성 예제 전용이니 실제 자료를 넣지 마세요.

## 개발

```bash
uv run pytest
```

테스트는 모델을 모의 처리하므로 GPU가 필요 없습니다. 코드는 [src/blacksite](src/blacksite/), 예제 설정과 운영 문서는 [demo](demo/)에 있습니다.

## 라이선스

Apache 2.0. [LICENSE](LICENSE)를 참고하세요.
