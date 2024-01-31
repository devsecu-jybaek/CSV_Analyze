# CSV_Analyze
 
 ESM 에서 다운 받은 로그파일을 보고서 양식에 맞게 데이터를 정제하는 프로그램.

 + 사내 보안 규정에 따라 고객사 정보 및 기타 개인 정보는 포함되지 않습니다.

 ### | 주요기능
 
    - 출발지 IP 통계
    - 목적지 IP 및 탐지 장비 IP 통계
    - 탐지된 공격 패턴명 통계
    - 출발지 IP의 국가 통계
    - 위험도 통계
    
 ### | History
    
    - 2023-10-14 Proto Type 초기코드 단계(기능 일부만 구현)
    - 2023-12-27 1.0.0 기본 기능 구현 완료. 
    - 2023-12-28 1.0.1 기존 코드에서 뷰 형식 변경 및 파일 선택 기능 추가. 폐쇄망 환경을 위해 Pyinstaller로 실행파일 생성.
    - 2023-12-29 ~ 2023-12-31 Error Fix(통계 분석 결과 기존 결과와 상이한 부분 존재하여 Fix)
    - 2024-01-09 특정 고객사 보고서 양식 변경에 의한 추가 기능 구현. 실행 환경을 고려하여 프로그램은 2type으로 나누어서 구현.
      (추후 여건이 될경우 UI를 통해 선택 실행할 수 있도록 통합 예정) 
    - 2024-01-26 위험도 카테고리에서 결측치 및 1,2로 출력되는 데이터들을 Info, High, Middle로 매핑되도록 변경
    - 2024-01-31 폐쇄망 환경을 위해 해당 파이썬 프로그램 및 패키지를 설치할 수 있도록 파일을 포함시키고 
                 배치파일을 생성하여 분석 방식 선택 과 프로그램&패키지 설치 및 제거 메뉴를 추가





## Release Note

| 버전     | 릴리스 날짜 | 주요 변경 사항                                   | 새로운 기능                                       | 개선된 기능                                        | 버그 수정                                      | 알려진 문제점                                 | 기타 변경 사항                                 |
|----------|-------------|---------------------------------------------------|---------------------------------------------------|---------------------------------------------------|-----------------------------------------------|------------------------------------------------|------------------------------------------------|
| 1.0.0 | 2023-12-27 | - 초기 릴리스 | - 기본 기능 전체 구현 완료 | - | -  | - 결측치 데이터에 대한 통계 미반영 | - |
| 1.1.0 | 2023-12-28 | - View 형태 변경 및 파일 선택 기능 구현 | - | - | - | - | - |
| 1.1.1 | 2023-12-31 | - Error Fix  | -  | - | - 결측치 데이터에 대한 통계 미반영에 대한 수정작업 완료 | - | - |
| 1.2.0 | 2024-01-09 | - 특정 고객사 양식 변경에 따른 2 Type 구현 | - 복합 분석 결과 파일 생성 추가 | - | - | - 복합 분석 결과에서 TOP3 추출 불가 | - |
| 1.3.0 | 2024-01-26 | - 복합 분석 결과 TOP3 추출 기능 구현 | - | - | - | - TOP3 추출 시 미정렬 문제 발생 | - |
| 1.3.1 | 2024-01-28 | - Error Fix | - 데이터 숫자 천단위 구분기호(,) 추가 | - | - TOP3 추출 시 정렬 문제 수정 작업 완료 | - | - |
