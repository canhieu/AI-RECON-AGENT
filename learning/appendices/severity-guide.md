# Severity Guide - INFO, LOW, MEDIUM, HIGH, CRITICAL

File này giải thích cách công cụ gán mức độ nghiêm trọng cho findings. Đây là phần cần nắm khi trình bày report trước hội đồng.

## Ai phụ trách phần này?

| Người | Trách nhiệm |
|---|---|
| Person 5 | Owner chính về policy/severity/safety, giải thích vì sao phân cấp như vậy |
| Person 3 | Giải thích severity trong dashboard/report khi demo |
| Person 2 | Hỗ trợ phần technical: severity được lưu trong SQLite và sinh từ parser/LLM/tool logic |

Nói ngắn:

- Person 5 trả lời câu hỏi lý thuyết/policy.
- Person 3 chỉ ra severity trong report/dashboard.
- Person 2 giải thích severity được lưu/chạy trong code thế nào.

## Severity là gì?

Severity là mức độ quan trọng/rủi ro của một finding. Nó giúp người đọc report biết nên ưu tiên xử lý hoặc điều tra finding nào trước.

```text
INFO < LOW < MEDIUM < HIGH < CRITICAL
```

## INFO

INFO là thông tin recon bình thường, chưa trực tiếp tạo rủi ro rõ ràng.

Ví dụ:

- Port mở nhưng chỉ là metadata ban đầu.
- Technology detected nhưng không có version.
- Redirect domain detected.
- HTTP title/status bình thường.
- CMS/framework detected nhưng chưa có version.

Ví dụ report:

```text
INFO: CMS/framework detected: CMS Made Simple
INFO: HTTP service discovered on port 80
```

Cách nói trước hội đồng:

> INFO không có nghĩa là vô dụng. Nó là dữ kiện nền để correlation và follow-up. Ví dụ biết target dùng CMS nào sẽ giúp chọn hướng kiểm tra tiếp theo.

## LOW

LOW là vấn đề nhẹ hoặc metadata có giá trị thấp, chưa đủ để tạo attack path rõ.

Ví dụ:

- Minor header issue.
- Low-value banner disclosure.
- Admin path exists nhưng chưa có version/credential/exposure.
- Non-sensitive directory discovered.

Ví dụ:

```text
LOW: Admin panel path exposed: /admin/
```

Cách nói:

> LOW thường là tín hiệu phụ. Nó có thể trở nên quan trọng nếu kết hợp với credential hoặc version vulnerable.

## MEDIUM

MEDIUM là thông tin disclosure hoặc exposure có thể hỗ trợ khai thác nhưng chưa chứng minh compromise.

Ví dụ:

- CMS/framework version exposed.
- Deprecated service version.
- Interesting backup path exists nhưng chưa tải được secret.
- Missing important security headers.
- API docs exposed without sensitive data.

Ví dụ:

```text
MEDIUM: CMS/framework version exposed: CMS Made Simple 2.2.21
MEDIUM: Interesting exposed artifact saved: config backup
```

Rule quan trọng trong project:

```text
Exposed CMS/framework version = at least MEDIUM
```

Cách nói:

> MEDIUM nghĩa là finding có thể dùng để định hướng khai thác. Ví dụ CMS version giúp tra CVE hoặc kiểm module/plugin tương ứng.

## HIGH

HIGH là finding có khả năng dẫn trực tiếp tới compromise hoặc chứa dữ liệu nhạy cảm, nhưng chưa nhất thiết là RCE đã xác nhận.

Ví dụ:

- Anonymous FTP/SMB access có sensitive files.
- Exposed credentials/secrets/configs.
- Private key detected.
- Database dump exposed.
- Redis unauthenticated data/config/key exposure.
- Proof-like artifact exposed.

Ví dụ:

```text
HIGH: Suspicious artifact reviewed: .env
HIGH: Artifact saved: credential from ftp://target/backup/.env
HIGH: Redis unauthenticated metadata and keys exposed
```

Cách nói:

> HIGH là finding cần ưu tiên vì nó có thể cung cấp credential, config, database hoặc sensitive data cho bước khai thác thủ công.

## CRITICAL

CRITICAL là finding thể hiện khả năng compromise rất cao hoặc đường khai thác nghiêm trọng rõ ràng.

Ví dụ:

- RCE path đã có evidence rõ.
- Auth bypass rõ.
- Valid exposed credentials có thể login critical service.
- Sensitive proof/flag/root artifact exposed trong CTF context.
- Direct path tới shell hoặc admin takeover, nếu exploit mode sau này xác nhận.

Hiện công cụ mặc định recon-only nên CRITICAL ít xuất hiện hơn HIGH. Nếu chưa exploit/confirm, thường giữ HIGH thay vì CRITICAL.

Cách nói:

> CRITICAL chỉ dùng khi evidence rất mạnh. Công cụ tránh phóng đại severity nếu chưa có bằng chứng rõ.

## Mapping nhanh

| Evidence | Severity thường dùng |
|---|---|
| Normal banner/status/title | INFO |
| CMS detected no version | INFO |
| CMS/framework version exposed | MEDIUM |
| Missing security header | MEDIUM/LOW tùy header/context |
| Admin path exposed only | LOW/INFO |
| Anonymous FTP no sensitive file | MEDIUM/HIGH tùy access |
| Anonymous FTP with configs/secrets | HIGH |
| `.env`, config with credential | HIGH |
| Private key | HIGH/CRITICAL tùy context |
| Database dump | HIGH |
| Redis unauthenticated data | HIGH |
| Confirmed RCE/auth bypass | CRITICAL |

## Severity trong code/report

Severity được lưu trong SQLite `findings.severity`.

```text
agent/state.py
  -> findings table

agent/orchestrator.py
  -> _save_analysis()
  -> deterministic CMS severity
  -> artifact severity

agent/reporter.py
  -> group findings by severity
```

Dashboard/report dùng severity để nhóm findings:

```text
CRITICAL Findings
HIGH Findings
MEDIUM Findings
LOW Findings
INFO Findings
```

## Ai nói gì khi bảo vệ?

### Person 5

Nói phần policy:

> Severity giúp ưu tiên findings. Công cụ phân biệt INFO/LOW/MEDIUM/HIGH/CRITICAL dựa trên mức độ evidence và tác động. Đặc biệt, exposed CMS version được xem ít nhất MEDIUM, còn exposed credential/config/artifact nhạy cảm là HIGH.

### Person 3

Nói phần report:

> Trong report, findings được nhóm theo severity để người đọc thấy vấn đề quan trọng trước. Dashboard cũng hiển thị severity live sau mỗi tool result.

### Person 2

Nói phần technical:

> Severity được lưu trong SQLite findings table. Một phần đến từ LLM analysis, một phần được set deterministic trong orchestrator, ví dụ CMS version exposed là MEDIUM và sensitive artifact là HIGH.

## Câu hỏi hội đồng có thể hỏi

Q: Vì sao CMS version là MEDIUM?

A: Vì version exposure giúp tra CVE và xác định hướng khai thác. Chưa có exploit confirmed nên không gán HIGH/CRITICAL mặc định.

Q: Vì sao credential artifact là HIGH?

A: Credential/config có thể dẫn trực tiếp tới truy cập service khác như SSH, database, CMS admin, nên phải ưu tiên cao.

Q: Vì sao không mọi finding đều HIGH?

A: Nếu gán quá cao cho mọi thứ thì report mất giá trị ưu tiên. Severity phải phản ánh tác động và evidence.

Q: INFO có cần quan tâm không?

A: Có. INFO là fact nền để correlation. Một INFO riêng lẻ có thể ít rủi ro, nhưng nhiều INFO kết hợp có thể tạo attack lead.
