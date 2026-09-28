# Blacksite

[English](README.md) | [한국어](README.ko.md)

로컬 LLM으로 돌리는 오프라인 장애 분석. 내 것도 아닌 블랙사이트 오두막에서 피할 수 없는 AGI 종말에 대비합니다. 은박지 모자는 별매.

![픽셀 아트로 그린 오프라인 작업 공간](assets/blacksite-homestead.png)

서버의 로그, 설정 파일, 명령 실행 결과를 넣으면 Blacksite가 읽기 전용 도구로 조사하고, 근거 로그 줄과 예상 결과, 되돌리기 절차를 담은 복구 가이드를 씁니다. 서버에서 명령을 실행할 수는 없습니다.

**Ollama, llama.cpp, vLLM**에서 동작하며 로컬 웹 앱과 CLI로 사용합니다.

## 데모

https://github.com/user-attachments/assets/07dc0837-7fa2-468e-a823-b9375bc70171

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

모든 명령은 `blacksite --help`로 볼 수 있습니다.

## 설정

`--config`로 TOML 파일을 지정합니다.

| 서버 | 예제 |
| --- | --- |
| Ollama | [demo/blacksite.toml](demo/blacksite.toml) |
| llama.cpp | [demo/llamacpp.toml](demo/llamacpp.toml) |
| vLLM | [demo/vllm.toml](demo/vllm.toml) |

모든 설정은 [blacksite.example.toml](blacksite.example.toml)에 설명되어 있습니다. 값 하나만 바꾸려면 `--set section.key=value`나 `BLACKSITE__SECTION__KEY` 환경 변수를 쓰고, 적용된 결과는 `blacksite config`로 확인하세요.

Blacksite는 이 컴퓨터에 있는 모델을 찾고, llama.cpp나 vLLM을 필요한 옵션과 함께 실행할 수 있습니다. 조사 전에 모델 서버를 점검하세요.

```bash
uv run blacksite models
uv run blacksite --config demo/llamacpp.toml serve model --from-ollama qwen3.8:27b-q4_K_M
uv run blacksite --config demo/llamacpp.toml check
```

웹 앱의 모델 선택 메뉴에도 같은 모델이 표시됩니다. 설정 파일이 없으면 Blacksite는 모델이 `blacksite`라는 이름으로 제공된다고 가정합니다. 이전 버전은 `holmes-local`을 기대했으니, 서버가 아직 그 이름을 쓰면 `model.name = "holmes-local"`로 설정하거나 `blacksite serve model`로 서버를 다시 시작하세요.

## 런북과 학습

세 가지 스위치로 팀의 지식을 조사에 더할 수 있습니다. 맥락을 더하면 오히려 에이전트가 나빠질 수도 있어서 모두 꺼진 채로 시작합니다. 직접 겪은 인시던트에서 기준선보다 나은 결과를 보일 때 켜세요. 웹 앱에서는 관리자가 사이드바에서 모든 사용자에게 적용되도록 설정하고, CLI는 설정 파일과 `--set`을 따릅니다.

| 스위치 | 설정 | 에이전트가 받는 것 |
| --- | --- | --- |
| 런북 검색 | `rag.enabled` | `rag.docs_dir`에 있는 Markdown과 텍스트 런북 검색 (데모는 [demo/knowledge](demo/knowledge/)) |
| 과거 장애 | `learning.cases.enabled` | 승인된 과거 장애 기록과 해결 방법 |
| 팀 플레이북 | `learning.playbook.enabled` | 에이전트 지침에 추가되는 승인된 교훈 |

런북 검색과 과거 장애는 에이전트가 필요할 때 도구로 호출합니다. 관련 내용을 처음부터 넣어 주려면 각각의 `mode = "inject"`로 설정하세요. 런북 검색은 키워드 순위(BM25)를 씁니다. `rag.retriever = "hybrid"`는 임베딩을(`uv sync --extra hybrid`로 설치), `rag.rerank = true`는 재순위화를 더하며, 둘 다 로컬 엔드포인트가 처리합니다. 런북이 바뀌면 색인은 저절로 다시 만들어집니다. `blacksite --config demo/blacksite.toml search "nginx 502"`로 시험해 보세요.

Blacksite는 사람이 보고한 결과에서만 배웁니다. 가이드를 따른 뒤 웹 앱에서 **해결되었나요?**에 답하거나 CLI를 사용하세요.

```bash
uv run blacksite --config demo/blacksite.toml learn record var/incidents/INC-1 --outcome resolved --notes "rollback fixed it"
uv run blacksite --config demo/blacksite.toml learn reflect var/incidents/INC-1
uv run blacksite --config demo/blacksite.toml learn review
uv run blacksite --config demo/blacksite.toml learn approve ID...
```

모델이 보고 내용으로 사례 기록과 플레이북 교훈 초안을 씁니다. 관리자가 **학습** 화면이나 `learn approve`로 승인하기 전에는 에이전트에게 전달되지 않습니다.

## 다른 에이전트에서 도구 쓰기

에이전트는 두 MCP 서버를 통해서만 증거를 봅니다. MCP를 지원하는 하네스라면 어디서든 이 서버들을 stdio로 실행할 수 있습니다.

```bash
uv run blacksite serve evidence var/incidents/INC-1
uv run blacksite --config demo/blacksite.toml serve knowledge --incident var/incidents/INC-1
```

- **evidence**는 인시던트 하나에 대한 읽기 전용 도구 다섯 개를 제공합니다: `list_artifacts`, `log_patterns`, `search_logs`, `read_lines`, `timeline`.
- **knowledge**는 도구 모드일 때 런북 검색이 켜져 있으면 `search_docs`와 `read_doc`을, 과거 장애가 켜져 있으면 `recall_cases`를 제공합니다. 스위치가 모두 꺼져 있으면 도구가 없으며, 이것이 기준선입니다.

`blacksite context --incident DIR`는 스위치가 에이전트 지침에 더하는 내용을 출력합니다.

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

- **계정.** 관리자는 **관리 → 멤버** 또는 `blacksite users add 이름`으로 멤버를 추가합니다. 새 멤버는 처음 로그인할 때 임시 비밀번호를 바꿉니다. 비밀번호 초기화, 계정 정지, 역할 변경, 세션 종료는 `blacksite users --help`를 참고하세요.
- **2단계 로그인**은 모두에게 꺼져 있으며, 등록한 계정의 인증 앱 설정과 복구 코드는 보관됩니다. 켜려면 `auth.totp_enabled = true`로 설정하고 재시작하세요. 기존 세션은 종료됩니다. 켜진 뒤에는 관리자는 인증 앱이 필수, 멤버는 선택입니다. 휴대폰을 잃어버리면 복구 코드를, 등록을 초기화하려면 `blacksite users reset-2fa 이름`을 사용하세요.
- **볼 수 있는 범위.** 멤버는 자신이 만들었거나 공유받은 인시던트만 봅니다. 관리자는 모두 보며, 모델, 스위치, 학습 승인은 관리자만 바꿉니다.
- **대시보드.** 열린 인시던트, 결과 대기 중인 가이드, 해결률, 가이드까지 걸린 시간(중앙값), 인용 확인 결과를 포함한 모델 실행 기록, 팀 활동을 보는 사람의 권한 범위 안에서 보여 줍니다.
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

테스트는 모델을 모의 처리하므로 GPU가 필요 없습니다. CI는 Linux, macOS, Windows에서 Python 3.11과 3.14로 테스트를 실행합니다.

| 경로 | 내용 |
| --- | --- |
| [src/blacksite/agent](src/blacksite/agent/) | 조사 루프, 그리고 사람에게 보이기 전에 가이드가 거치는 검증 |
| [src/blacksite/evidence](src/blacksite/evidence/) | 로그 파싱, 비밀 값 가리기, 증거 색인과 MCP 서버 |
| [src/blacksite/knowledge](src/blacksite/knowledge/) | 런북 검색과 knowledge MCP 서버 |
| [src/blacksite/learning](src/blacksite/learning/) | 결과 보고, 회고, 사례와 교훈 저장소 |
| [src/blacksite/auth](src/blacksite/auth/), [audit](src/blacksite/audit/) | 계정과 로그인, 감사 기록, 가이드 출처 |
| [src/blacksite/web](src/blacksite/web/) | 웹 앱: API, 대시보드, 관리 콘솔, 프런트엔드 |
| [src/blacksite](src/blacksite/) | CLI, 설정, 모델 서버와 점검, USB 모드, 내보내는 보고서 |
| [tests](tests/) | 테스트, 그리고 `tests/fixtures/`의 합성 예제 인시던트와 런북 |
| [demo](demo/) | 예제 설정, Ollama Modelfile, 예제 런북 |
| [scripts](scripts/) | 데모 영상 녹화와 배너 이미지 생성 도구 |

## 라이선스

Apache 2.0. [LICENSE](LICENSE)를 참고하세요.
