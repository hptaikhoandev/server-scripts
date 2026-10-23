bash wp-incident-fix.sh botusers            # đếm user bot trên mọi site
bash wp-incident-fix.sh botusers-apply      # xoá user bot
bash wp-incident-fix.sh dbpass [domain]     # đổi mật khẩu DB, tự trả lại mật khẩu cũ nếu lỗi
bash wp-incident-fix.sh traplog             # xem bẫy đã bắt được gì
ROTATE_DB=1 bash wp-incident-fix.sh all     # chạy trọn quy trình + đổi mật khẩu DB mọi site
