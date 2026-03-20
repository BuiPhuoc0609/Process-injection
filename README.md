# Process-injection

```
Yêu cầu: Lập trình và demo inject PE file vào tiến trình bất kỳ
```

## DLL Injection

Ý tưởng: inject shellcode có chức năng tìm địa chỉ `LoadLibraryA` để load DLL vào process đích và gọi DLL main

### Chuẩn bị DLL

Ta sẽ tạo 1 dll gọi messagebox để inject vào process


```c
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "Hello World!", "DLL Loaded", MB_OK | MB_ICONINFORMATION);
        break;
```

### Injector

Các bước thực hiện:

- tạo 1 process bằng `CreateProcessA` để lấy process handle
- cấp phát 1 vùng nhớ trên process đích với protect `rwx` bằng `VirtualAllocEx` vì `VirtualAllocEx` có thể cấp phát trên process bất kỳ qua process handle còn `VirtualAlloc` thì không
- ghi shellcode vào process đích bằng `WriteProcessMemory` với address là địa chỉ được trả về từ `VirtualAllocEx` trên
- tạo thread mới trên process bị inject bằng `CreateRemoteThread` để gọi shellcode
- đóng các handle

### Shellcode

Shellcode được viết bằng C, tuy nhiên không có các hàm init C, không dùng import, dùng biến local trong stackframe và compiler sử dụng địa chỉ tương đối (ví dụ call, mov,... tương đối) nên ta có thể dump code ra từ file pe đã compiled làm shellcode

Các bước thực hiện:
- sử dụng kỹ thuật [PEB walking](https://fareedfauzi.github.io/2024/07/13/PEB-Walk.html) để resolve API  `LoadLibraryA`
- parse dll để tìm DLLMain
- gọi DLLMain

### Ngoài lề

Ngoài cách viết shellcode để gọi `LoadLibaryA` như trên thì còn có kỹ thuật khác hay được sử dụng hơn để lấy address `LoadLibaryA`

Tham khảo:

https://sec.vnpt.vn/2019/01/dll-injection

<img width="603" height="595" alt="image" src="https://github.com/user-attachments/assets/d2419572-7fef-40c3-8d66-a0ca6a9e1248" />

Như ta có thể thấy ở trên rõ ràng chương trình lấy address của `LoadLibraryA` trên process injector nhưng lại có thể lấy nó để gọi trên process bị inject

Vậy có nghĩa là base address kernel32 của 2 process đều giống nhau

Tham khảo sách Windows Internals part 1, 7th edition:

<img width="588" height="724" alt="image" src="https://github.com/user-attachments/assets/7d3ee011-dcb1-43bb-b545-0bd6f1d222f1" />

Có nghĩa là Windows không cần load nhiều bản copy của cùng một DLL vào RAM mà chỉ load 1 lần với protect r-x rồi các process khác nhau sẽ cùng trỏ vào nó để thực thi để tối ưu memory

Trong trường hợp 1 process đổi protect để write/patch dll thì windows sẽ sử dụng cơ chế copy-on-write để tạo bản copy riêng cho process đó để sử dụng

Như vậy kỹ thuật Dll Injection đã lợi dụng cơ chế này để lấy address winapi dù là process khác nhau

### Thực nghiệm

Thực thi Injector:

<img width="1109" height="618" alt="image" src="https://github.com/user-attachments/assets/0e54a51f-fc5a-4596-a0ab-cb3dc5b30dff" />

Ta thấy messagebox từ DLL bị inject đã được gọi
