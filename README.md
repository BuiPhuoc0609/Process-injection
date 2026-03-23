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

Shellcode được viết bằng C, tuy nhiên không có các hàm init C, không dùng import, dùng biến local trong stackframe và compiler sử dụng địa chỉ tương đối (ví dụ call, jmp,... tương đối) nên ta có thể dump code ra từ file pe đã compiled làm shellcode

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

## Process Hollowing

Ý tưởng: Dừng process trước khi main thread chạy, mapping pe file mới vào process, đổi entrypoint và đổi ImageBase trong PEB để Windows loader tự resolve API

### Loader

tham khảo: https://sec.vnpt.vn/2019/01/process-hollowing

Nghiên cứu kết hợp với kỹ thuật map pefile bằng `CreateSection` + `NtMapViewOfSection` để map từ `file object -> section object -> section image` thay cho manual mapping truyền thống của kỹ thuật Process Ghosting

Bài báo cáo của em và nhóm tại trường về kỹ thuật Process Ghosting: https://github.com/BuiPhuoc0609/Process-injection/blob/main/Bao%20cao%20Process%20Ghosting.docx

Các bước thực hiện:
- tạo 1 process bình thường để lấy handle process
- lấy PEB của process bị inject bằng `NtQueryInformationProcess`
- đọc PEB bằng `ReadProcessMemory` và lấy `ImageBase` của process bị inject
- parse header và lấy `AddressOfEntryPoint`
- lấy file handle của chương trình sắp inject bằng `CreateFileA`
- tạo Section Object bằng `NtCreateSection` với file handle và cờ `SEC_IMAGE`
- map file pe lên mem bằng `NtMapViewOfSection` với Section handle vừa tạo
- parse entrypoint của image vừa inject
- patch lệnh jmp tuyệt đối tại entry point cũ để jmp vào entry point mới
- Sửa imagebase trong PEB để Windows loader resolve API
- ResumeThread để chương trình tiếp tục thực thi

### Một số cải tiến so với kỹ thuật process hollowing cũ

Thay vì phải virtual alloc và parse từng section, relocation để map pe file lên manual thì ta sử dụng `NtCreateSection` + `NtMapViewOfSection` để windows tự map lên memory của process

Buộc phải Create Section với file handle và `SEC_IMAGE` để phân biệt với kỹ thuật https://www.ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection chỉ có thể inject shellcode chứ không tự map pe file 

Lợi thế là ta có thể inject PEfile có size lớn hơn pe cũ

```c
HANDLE hFile = CreateFileA("lmao.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
HANDLE hSection;
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);

PVOID newBaseAddress = NULL; 
SIZE_T viewSize = 0;
NtMapViewOfSection(hSection, pi.hProcess, &newBaseAddress, 0, 0, NULL, &viewSize, 1, 0, PAGE_READONLY);
```

Do không phải unmap image cũ nên ta sẽ patch vào địa chỉ entry point cũ trỏ đến thành lệnh jmp tuyệt đối đến entrypoint mới thay vì sửa thread context bằng `SetThreadContext`

```c
BYTE patch[12] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 }; //patch jmp den entrypoint moi vao entrypoint cu
memcpy(&patch[2], &newEntryPoint, 8);

DWORD oldProtect;
VirtualProtectEx(pi.hProcess, hostEntryPoint, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
WriteProcessMemory(pi.hProcess, hostEntryPoint, patch, sizeof(patch), NULL);
```

Để Windows loader có thể resolve import thì ta phải sủa `ImageBaseAddress` của PEB thành base mới do `NtMapViewOfSection` trả về, khi main thraed được resume thì iat sẽ được resolve

Có thể kết hợp set file information `Delete Pending` như kỹ thuật process ghosting để tránh file malware chưa kịp inject thì đã bị quét và xóa

## Thực nghiệm

<img width="1115" height="615" alt="image" src="https://github.com/user-attachments/assets/75344838-145a-49a2-ae43-ce48c8c1da18" />

Image cũ và Image mới được inject vào

<img width="1923" height="782" alt="image" src="https://github.com/user-attachments/assets/9ff56633-0719-45a3-83f3-10c275605262" />

IAT của image cũ (cmd.exe) không được resolve:

<img width="1919" height="1005" alt="image" src="https://github.com/user-attachments/assets/26e2e680-456b-4e5f-ac82-34d4082db6dd" />

Image mới đã được resolve IAT vìa sửa ImageBase trong PEB:

<img width="1912" height="1007" alt="image" src="https://github.com/user-attachments/assets/c3e27512-2da3-4492-9a42-e955ac4a9b1a" />

New code:

<img width="1919" height="1001" alt="image" src="https://github.com/user-attachments/assets/650b7d99-76fe-4aa7-afd7-2f9112507457" />
