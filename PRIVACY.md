# Munimen Privacy Policy

Updated 17 November 2026 · [한국어](#munimen-개인정보-처리-안내)

Munimen inspects link and address-bar hostnames and email originals that you choose to inspect, on your device. It does not use an LLM. The inspection service does not upload visited URLs, search terms, email content or passwords to the operator or a reputation service.

## Local processing and storage

The extension stores reference data, verified threat data and their revisions, settings, temporary verdicts and warning state locally in your Chrome profile. Errors and timing diagnostics remain local and are not automatically reported.

A local comparison cache can retain up to 5,000 hostname-level records for 7 days. Records contain hostnames, comparison output and creation/expiry times; they can reveal domain-level browsing traces. They do not contain paths, queries, search terms, email bodies, visit counts or ignored-warning approvals. They are not synchronized to other devices or accounts. Hover-only inspections do not create these stored records. Expired records are removed during subsequent cache initialization or access.

The current beta supports normal Chrome windows. It cannot be enabled in incognito mode. Removing the extension removes its Chrome extension storage; separately exported files must be deleted separately.

## Threat-list downloads

Munimen checks for signed JSON threat-list updates at startup and periodically, normally hourly, from the public GitHub Releases repository [poohpak/munimen-threat-data](https://github.com/poohpak/munimen-threat-data). These requests contain no visited domain, search term or mail content, and no user identifier is added. GitHub receives ordinary network connection information such as your IP address. Downloaded data is authenticated before it becomes active; remote executable code is not downloaded.

## Email inspection

Selected email originals are parsed locally. Gmail integration operates in Gmail's original-message view. SPF, DKIM and DMARC results are interpreted from the receiving system's recorded headers; arbitrary pasted headers are not independently authenticated by Munimen.

## Voluntary support messages

The feedback screen builds a draft from your chosen message, optional hostname and extension version. It does not automatically read the current tab or attach email originals. The optional domain field removes URL credentials, path, query and fragment. Text that you independently type into your message remains part of your chosen message.

The extension does not send the message automatically. You review and send it through your selected email service. If you send a support email, the support operator receives your sender address, message and any attachments you choose to include, to respond to the request. Support emails are held in the support mailbox rather than the extension's local cache. To request deletion of a support email, contact the support address below.

## Limited use

Munimen’s use of information received from Google APIs follows the Chrome Web Store User Data Policy, including the Limited Use requirements. User data is used for the described inspection and support features, not for advertising or unrelated profiling.

## Contact

Munimen support: [consilience.labs@gmail.com](mailto:consilience.labs@gmail.com)

# Munimen 개인정보 처리 안내

Munimen은 링크·주소창의 호스트와 사용자가 선택한 메일 원본을 기기 안에서 검사합니다. LLM을 사용하지 않습니다. 검사 서비스는 방문 주소, 검색어, 메일 내용, 비밀번호를 운영자나 평판 서비스로 자동 전송하지 않습니다.

## 기기 안의 처리와 저장

참고 자료, 검증한 위협 자료와 버전, 설정, 임시 판정과 경고 상태는 Chrome 프로필에 저장합니다. 오류와 처리 시간도 자동 전송하지 않습니다.

호스트별 비교 결과는 최대 5,000개를 7일간 로컬 캐시에 보관할 수 있습니다. 호스트명과 비교 결과·생성/만료 시각은 도메인 단위의 이용 흔적이 될 수 있습니다. 경로·쿼리·검색어·메일 본문·방문 횟수·경고 무시 승인은 이 캐시에 저장하지 않고 다른 기기나 계정에 동기화하지 않습니다. 링크에 마우스만 올린 경우는 새 캐시 기록을 저장하지 않습니다. 만료 기록은 다음 캐시 초기화나 조회 때 제거합니다.

이번 베타는 일반 Chrome 창을 지원하며 시크릿 모드에서는 활성화할 수 없습니다. 확장을 제거하면 Chrome의 확장 저장소가 삭제됩니다. 별도로 내보낸 파일은 사용자가 따로 삭제해야 합니다.

## 위협 자료 다운로드

시작 시와 주기적으로(일반적으로 매시간) 공개 GitHub Releases 저장소 [poohpak/munimen-threat-data](https://github.com/poohpak/munimen-threat-data)에서 서명된 JSON 자료의 갱신을 확인합니다. 요청에는 방문 도메인·검색어·메일 내용이나 별도 사용자 식별자를 넣지 않습니다. GitHub에는 IP 주소 등 일반 연결 정보가 전달됩니다. 자료는 인증 후 적용하며 원격 실행 코드를 내려받지 않습니다.

## 메일 검사

선택한 메일 원본은 로컬에서 분석합니다. Gmail 연동은 원본 보기 화면에서 동작합니다. SPF·DKIM·DMARC는 수신 시스템이 기록한 헤더를 해석하며 임의로 붙여넣은 헤더를 독립 검증된 인증으로 표시하지 않습니다.

## 사용자가 선택한 문의

제보 화면은 사용자가 작성한 내용·선택 입력한 호스트·확장 버전으로 초안을 만듭니다. 현재 탭이나 메일 원문을 자동으로 읽어 첨부하지 않습니다. 도메인 입력에서는 사용자 정보·경로·쿼리·프래그먼트를 제거합니다. 사용자가 문의 본문에 직접 작성한 내용은 그대로 포함됩니다.

확장은 메일을 자동 발송하지 않습니다. 사용자가 선택한 메일 서비스에서 검토하고 발송합니다. 지원 메일을 보내면 응대를 위해 발신 주소, 문의 내용과 사용자가 첨부한 파일을 받습니다. 지원 메일은 로컬 캐시와 별도로 지원 메일함에 보관됩니다. 문의 메일 삭제 요청은 아래 연락처로 보내 주세요.

## 사용 목적 제한

Google API를 통해 받은 정보는 Chrome 웹 스토어 사용자 데이터 정책의 제한적 사용 요건을 따릅니다. 사용자 데이터는 설명한 검사·지원 기능에 사용하며 광고나 관련 없는 프로파일링에 사용하지 않습니다.

## 문의

[consilience.labs@gmail.com](mailto:consilience.labs@gmail.com)
