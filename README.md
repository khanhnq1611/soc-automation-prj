# Báo cáo Project SOC Automation (SIEM SOAR)
## Mô hình thiết kế
 ![alt text](<Screenshot 2025-08-07 014722.png>)
 Máy Windows/Ubuntu Client, 
 Máy Wazuh Server, 
 Máy thehive server
![alt text](image-17.png)

Trong workflow này tất cả mọi hành động đều được thực hiện qua hệ thống SOAR dùng shuffle. 

hệ thống sẽ dùng rule truy xuất từ logs để phát hiện mối đe dọa đến máy client (được cài wazuh agent ), kiểm tra thông tin hash trên virustotal để làm giàu thông tin,

sau đó gửi báo cáo về thehive để quản lí case các sự kiện, rồi sẽ tự động chặn ip tới nguồn độc hại bằng cách dùng agent-control trong wazuh server.

Đây là homelab mang tính demo SIEM, SOAR, endpoint agent, tuy chưa được hoàn thiện lắm nhưng cũng khá là hữu ích cho người mới! 