# @smart-ppe/common (smart-ppe-shared-contracts)

> **Shared Contracts, Kafka Event Schemas, Constants, Types, and Core Utilities** cho toàn bộ hệ thống Microservices Giám sát An toàn Lao động Thông minh (**Smart PPE Monitoring System**).

Tài liệu này hiện thực hóa yêu cầu của **Task ALL-03 (Chốt AI → Violation Event Contract)** và phân rã hệ thống theo kiến trúc **Microservices (Chuẩn D08.pdf)**.

---

## 📦 Cài đặt (Installation)

Các microservices (`identity`, `site`, `camera`, `incident`, `notification`, `media`, `reporting`) và client có thể cài đặt thư viện này theo các cách sau:

### 1. Cài đặt trực tiếp qua Git URL (Khuyên dùng)
```bash
pnpm add git+https://github.com/smart-ppe-monitoring/smart-ppe-shared-contracts.git
# hoặc
npm install git+https://github.com/smart-ppe-monitoring/smart-ppe-shared-contracts.git
```

### 2. Dùng trong môi trường phát triển cục bộ (Local Development)
Nếu các repo nằm cạnh nhau trong cùng máy:
```bash
cd smart-ppe-site-service
pnpm add ../smart-ppe-shared-contracts
```

---

## 🏛️ Cấu trúc thư viện

```text
src/
├── constants/       # Tất cả hằng số nghiệp vụ, Roles, Permissions, Kafka Topics, Gateway
├── errors/          # Lớp AppError chuẩn và bảng mã lỗi ERROR_CODE tập trung
├── types/           # Type định danh Kafka Events, phân trang, sự kiện hệ thống
├── validations/     # Zod Schemas validate sự kiện Kafka (Task ALL-03) và UUID
├── helpers/         # UUIDv7 monotonic, SSRF defense, Crypto timing-safe, Date (UTC+7)
└── index.ts         # Main Entrypoint xuất bản toàn bộ contracts
```

---

## 🚀 Hướng dẫn sử dụng

### 1. Sử dụng Kafka Event Schemas (Task ALL-03 Contract)
```typescript
import { 
  ppeViolationDetectedKafkaEventSchema, 
  PPEViolationDetectedKafkaEvent,
  KAFKA_TOPICS 
} from "@smart-ppe/common";

// Validate payload nhận được từ Kafka topic
const result = ppeViolationDetectedKafkaEventSchema.safeParse(rawMessage);
if (result.success) {
  const event: PPEViolationDetectedKafkaEvent = result.data;
  console.log(`Đã phát hiện vi phạm: ${event.payload.violationType} tại camera ${event.payload.cameraId}`);
}
```

### 2. Sử dụng Constants & Phân quyền động (Dynamic RBAC)
```typescript
import { PERMISSIONS, ROLES, PPE_INCIDENT_STATUS } from "@smart-ppe/common";

if (user.role === ROLES.SAFETY_OFFICER) {
  // Thực thi nghiệp vụ...
}
```

### 3. Xử lý Lỗi tập trung (Error Handling)
```typescript
import { AppError, ERROR_CODE } from "@smart-ppe/common";

throw new AppError(
  "Không tìm thấy công trường",
  404,
  ERROR_CODE.NOT_FOUND
);
```

### 4. Tiện ích chuẩn mật mã & định danh
```typescript
import { uuidv7, isPrivateOrReservedIp } from "@smart-ppe/common";

const newId = uuidv7(); // UUIDv7 chuẩn RFC 9562 tối ưu B-Tree index
```

---

## 🛠️ Biên dịch thư viện (Build)

```bash
# Cài đặt dependencies
pnpm install

# Biên dịch TypeScript sang JavaScript & .d.ts declarations
pnpm run build
```

---

## 📜 Giấy phép & Bản quyền
Đồ án Tốt nghiệp: Hệ thống Giám sát An toàn Lao động Thông minh trên nền tảng Microservices (Chuẩn D08.pdf).
Tổ chức GitHub: [smart-ppe-monitoring](https://github.com/smart-ppe-monitoring).
