OWASP 4.1.1: Trinh sát bằng Công cụ Tìm kiếm (Search Engine Discovery Reconnaissance)1. Tổng quan Lý thuyếtMục tiêuMục tiêu của giai đoạn này là sử dụng các công cụ tìm kiếm công khai (như Google, Bing, DuckDuckGo, Baidu...) để tìm kiếm các thông tin nhạy cảm về ứng dụng web mục tiêu mà có thể đã bị vô tình công khai.Đây là kỹ thuật Passive Reconnaissance (Trinh sát thụ động). Người kiểm thử không tương tác trực tiếp với máy chủ của mục tiêu, do đó giảm thiểu rủi ro bị phát hiện bởi tường lửa (WAF) hoặc hệ thống IDS/IPS.Tại sao thông tin lại bị rò rỉ trên Google?Các công cụ tìm kiếm sử dụng "spiders" hoặc "bots" để thu thập dữ liệu (crawl) và lập chỉ mục (index) mọi thứ chúng tìm thấy. Rò rỉ xảy ra khi:Quản trị viên cấu hình sai quyền truy cập.File robots.txt không chặn các thư mục nhạy cảm.Các trang web tạm thời (staging/dev) vô tình được public.Các thông báo lỗi chứa thông tin hệ thống bị index.Công cụ chính: Google Hacking (Google Dorking)Kỹ thuật sử dụng các toán tử tìm kiếm nâng cao để lọc kết quả chính xác được gọi là Google Dorking.Các toán tử cơ bản:site:example.com - Giới hạn kết quả chỉ trong tên miền mục tiêu.filetype:pdf (hoặc ext:pdf) - Chỉ tìm loại file cụ thể (pdf, xls, doc, sql, log...).inurl:admin - Tìm từ khóa nằm trong URL.intitle:"index of" - Tìm từ khóa nằm trong tiêu đề trang.intext:"password" - Tìm từ khóa nằm trong nội dung trang.cache:example.com - Xem phiên bản lưu trữ (cache) của Google về trang web (hữu ích khi trang gốc đã bị xóa hoặc sửa).- (Dấu trừ) - Loại trừ từ khóa (VD: -site:www.example.com để tìm các subdomain khác ngoài www).2. Các Kịch bản Kiểm thử (Test Cases) và Ví dụDưới đây là các nhóm kịch bản phổ biến nhất mà Pentester cần thực hiện.Lưu ý: Thay thế target.com bằng tên miền mục tiêu của bạn.Kịch bản 1: Tìm kiếm các tệp tin cấu hình và sao lưu (Configuration & Backup Files)Các tệp này thường chứa mật khẩu DB, cấu trúc hệ thống hoặc logic code.Tìm file Log:site:target.com ext:log
site:target.com filetype:log intext:"password"
site:target.com filetype:log intext:"error"
Tìm file Cấu hình (Config):site:target.com ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ini
site:target.com filetype:env (Tìm file environment thường chứa API Key/DB pass)
Tìm file Backup dữ liệu:site:target.com ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup
site:target.com filetype:sql (Rất nguy hiểm: chứa dump database)
Kịch bản 2: Tìm kiếm Trang Quản trị và Cổng đăng nhập (Login & Admin Panels)Tìm các cổng đăng nhập không được liên kết từ trang chủ để thực hiện tấn công Brute Force sau này.Tìm trang Admin:site:target.com inurl:admin
site:target.com intitle:"admin login"
site:target.com inurl:login
site:target.com intitle:"Quản trị hệ thống"
Tìm cổng VPN hoặc Webmail:site:target.com inurl:vpn
site:target.com inurl:webmail
Kịch bản 3: Phát hiện "Directory Listing" (Liệt kê thư mục)Nếu server cấu hình sai, kẻ tấn công có thể nhìn thấy toàn bộ cấu trúc file.Tìm Index of:site:target.com intitle:"index of"
site:target.com "parent directory"
Kết hợp tìm file trong thư mục:site:target.com intitle:"index of" "backup"
site:target.com intitle:"index of" "secret"
Kịch bản 4: Tìm thông báo lỗi lộ thông tin (Error Message Leakage)Thông báo lỗi mặc định thường tiết lộ phiên bản Server, Database hoặc đường dẫn vật lý (Physical Path).Lỗi SQL:site:target.com intext:"sql syntax near"
site:target.com intext:"syntax error has occurred"
site:target.com intext:"incorrect syntax near"
Lỗi PHP/System:site:target.com "Fatal error:"
site:target.com "Warning: include"
site:target.com "unexpected end of file"
Kịch bản 5: Tìm tài liệu nhạy cảm công khai (Publicly Exposed Documents)Tìm các tài liệu nội bộ vô tình được upload lên thư mục public.Tìm tài liệu văn phòng:site:target.com ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv
Tìm bảng tính (thường chứa danh sách khách hàng/nhân viên):site:target.com ext:xls | ext:xlsx intext:"email"
site:target.com ext:xls intext:"password"
Kịch bản 6: Tìm kiếm Subdomain (Subdomain Enumeration)Tìm các tên miền phụ bị lãng quên (Dev, Staging, Test).Loại trừ trang chính:site:target.com -www
site:target.com -www.target.com
Kịch bản 7: Tìm kiếm mã nguồn (Source Code) bị lộĐôi khi developer upload cả file mã nguồn lên server.Tìm file code:site:target.com ext:php intitle:phpinfo "published by the PHP Group"
site:target.com ext:java | ext:py | ext:rb | ext:c | ext:cpp
Tìm các file từ repository:site:target.com inurl:.git
site:target.com inurl:.svn
3. Các cơ sở dữ liệu Dorking khác (Ngoài Google)Ngoài Google, bạn nên kiểm tra:Google Hacking Database (GHDB): https://www.exploit-db.com/google-hacking-databaseĐây là kho tàng chứa hàng ngàn Dork được cộng đồng cập nhật liên tục.Wayback Machine (Archive.org):Tìm kiếm các phiên bản cũ của website. Đôi khi file nhạy cảm đã bị xóa trên trang hiện tại nhưng vẫn còn lưu trong quá khứ.Shodan.io:Tìm kiếm các thiết bị (IoT, Server, Webcam) kết nối Internet liên quan đến IP của mục tiêu.GitHub:Tìm kiếm xem developer có lỡ tay push API key hay credentials lên GitHub public không (Sử dụng tool như GitRob hoặc TruffleHog).4. Biện pháp phòng ngừa (Remediation)Sau khi kiểm thử và phát hiện vấn đề, cần đề xuất giải pháp cho khách hàng/đội dự án:Cấu hình file robots.txt: Chặn bot tìm kiếm truy cập vào các thư mục admin, backup, private (Lưu ý: Đây không phải là biện pháp bảo mật tuyệt đối, chỉ là chỉ dẫn cho bot ngoan).Sử dụng thẻ Meta Tag: Thêm <meta name="robots" content="noindex, nofollow"> vào header của các trang nhạy cảm.Xác thực (Authentication): Đảm bảo mọi tài nguyên nhạy cảm đều yêu cầu đăng nhập mới xem được.Vô hiệu hóa Directory Listing: Tắt tính năng liệt kê thư mục trong cấu hình Web Server (Apache/Nginx/IIS).Google Search Console: Sử dụng công cụ này để yêu cầu Google gỡ bỏ các URL nhạy cảm đã bị index khỏi kết quả tìm kiếm.Quy trình CI/CD: Kiểm tra tự động để đảm bảo không có file backup, file log hay file .git bị đẩy lên môi trường Production.