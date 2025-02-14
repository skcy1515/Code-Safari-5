# Code-Safari-5
코드 사파리 1기 과정 5팀 프로젝트 리포지토리입니다.

- 개발 기간: 2025/02/10 ~ 2025/02/13
- 주제: 코드 사파리 교육생들 간의 소통창구 제공을 위한 세션인증 기반 게시판 사이트

# 멤버
- `skcy1515` : 김찬영, 백엔드 담당
- `Jsowon` : 장소원, 프론트엔드 담당
- `Y0ungOne` : 안수연, 프론트엔드 담당

# 사용한 기술
![KakaoTalk_20250214_154644059](https://github.com/user-attachments/assets/7fecc70c-dec7-4e0b-a787-c49fa9a84b7c)

# 구현한 기능들
## 로그인 (sign_in.html)
![image](https://github.com/user-attachments/assets/31aadd30-7864-44d8-bb79-22c7d12681f8)

- DB에 저장된 사용자의 정보를 바탕으로 로그인 기능 수행
- 로그인 정보는 세션 (사용자의 브라우저)에 저장됨

## 회원가입 (sign_up.html)
![image](https://github.com/user-attachments/assets/6cb6a40d-6ed1-4415-851a-16eb11b1e04c)

- 입력한 정보를 바탕으로 회원가입 기능 수행
- 사용자의 정보가 DB에 저장됨

## 메인화면 (index.html)
![image](https://github.com/user-attachments/assets/8f21358e-8881-4a61-9951-59b3391c271e)

- 사용자들이 작성한 게시글들이 표시됨
- 마이페이지, 게시글작성, 로그아웃, 제목 키워드 검색, 좋아요 순으로 정렬을 할 수 있음

## 마이페이지 (mypage.html)
![image](https://github.com/user-attachments/assets/2ead9412-fcbe-4ae5-9e4d-39e5ec97f1f9)

- 사용자의 정보 표시
- 회원정보 수정, 내 게시글 조회, 회원탈퇴를 수행할 수 있음

## 회원정보 수정 (edit_profile.html)
![image](https://github.com/user-attachments/assets/273d022e-01e5-415a-b217-6b9268fed2d1)

- 사용자의 비밀번호를 수정할 수 있음

## 내 게시글 조회 (view_post)
![image](https://github.com/user-attachments/assets/1a6c6bed-a112-4442-80cb-576d71013543)

- 내가 작성한 게시글들을 볼 수 있음

## 게시글 작성 (post_write.html)
![image](https://github.com/user-attachments/assets/e531029b-56e8-4508-8749-0db336527646)

- 게시글을 작성할 수 있음
- 파일을 1개까지 올릴 수 있음

## 게시글 조회 (post_show.html)
![image](https://github.com/user-attachments/assets/4bfb714f-01b7-40c1-83dd-a5ef2d4d9b5d)

- 게시글을 조회할 수 있음
- 업로드한 파일이 사진이면 사진 형식으로 제공되고, 사진이 아니면 다운로드 형식으로 제공됨
- 세션인증을 통해 댓글 작성, 댓글 삭제, 게시글 수정, 게시글 삭제 기능을 수행할 수 있음
- 하루에 한 번 좋아요를 누를 수 있음

## 게시글 수정 (post_edit.html)
![image](https://github.com/user-attachments/assets/b5c1d360-0df6-47ec-abcb-5afded01829c)

- 업로드 된 게시글의 정보를 불러와서 게시글 수정을 할 수 있음
- 파일을 다른 파일로 바꾸거나, 파일 삭제를 할 수 있음
