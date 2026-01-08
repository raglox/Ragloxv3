# 🚀 دليل الاختبار السريع - RAGLOX v3.0

## 🌐 روابط الوصول المباشرة

### واجهة الـ API
- **الصفحة الرئيسية**: http://208.115.230.194:8000
- **الوثائق التفاعلية (Swagger)**: http://208.115.230.194:8000/docs
- **التوثيق المفصل (ReDoc)**: http://208.115.230.194:8000/redoc
- **فحص الصحة**: http://208.115.230.194:8000/health

### Firecracker Manager
- **API Endpoint**: http://208.115.230.194:8080

---

## ⚡ الاختبار السريع (5 دقائق)

### 1. افتح الوثائق التفاعلية
زر الرابط: http://208.115.230.194:8000/docs

### 2. اختبر Health Endpoint
```bash
# في المتصفح أو Terminal
curl http://208.115.230.194:8000/health
```

**النتيجة المتوقعة**:
```json
{
  "status": "degraded",
  "components": {
    "api": "healthy",
    "blackboard": "unhealthy",
    "knowledge": "loaded"
  }
}
```

### 3. سجل حساب جديد

**Endpoint**: `POST /api/v1/auth/register`

**الطلب**:
```json
{
  "email": "admin@raglox.local",
  "password": "SecurePassword123!",
  "organization_name": "RAGLOX Security",
  "plan": "professional"
}
```

**كيفية الاختبار عبر Swagger UI**:
1. انقر على `POST /api/v1/auth/register`
2. انقر "Try it out"
3. الصق JSON أعلاه
4. انقر "Execute"

### 4. سجل الدخول

**Endpoint**: `POST /api/v1/auth/login`

**الطلب**:
```json
{
  "username": "admin@raglox.local",
  "password": "SecurePassword123!"
}
```

**النتيجة المتوقعة**:
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "user": {
    "id": "...",
    "email": "admin@raglox.local",
    "role": "admin",
    "organization_id": "..."
  }
}
```

**⚠️ احفظ الـ `access_token` لاستخدامه في الطلبات التالية!**

### 5. استخدم الـ Token

في أعلى صفحة Swagger UI:
1. انقر على زر **"Authorize"** 🔓
2. أدخل: `Bearer YOUR_ACCESS_TOKEN`
3. انقر "Authorize"
4. انقر "Close"

الآن جميع الـ endpoints المحمية جاهزة للاستخدام!

---

## 🧪 سيناريوهات الاختبار المتقدمة

### سيناريو 1: إنشاء بيئة Sandbox

**Endpoint**: `POST /api/v1/environments`

**الطلب**:
```json
{
  "environment_type": "sandbox",
  "name": "pentest-env-01",
  "vm_config": {
    "vcpu": 2,
    "mem_mib": 2048,
    "disk_mb": 10240
  }
}
```

**النتيجة المتوقعة**:
```json
{
  "environment_id": "env-...",
  "status": "creating",
  "vm_instance": {
    "vm_id": "vm-...",
    "ip_address": "172.30.0.x",
    "status": "running"
  }
}
```

---

### سيناريو 2: إنشاء مهمة Red Team

**Endpoint**: `POST /api/v1/missions`

**الطلب**:
```json
{
  "name": "Reconnaissance Mission",
  "description": "Full reconnaissance of target infrastructure",
  "target": "example.com",
  "ttps": [
    "T1595",
    "T1590",
    "T1592"
  ],
  "mode": "automatic",
  "safety_mode": true,
  "max_depth": 3
}
```

**النتيجة المتوقعة**:
```json
{
  "mission_id": "mission-...",
  "name": "Reconnaissance Mission",
  "status": "pending",
  "created_at": "2026-01-08T12:00:00Z",
  "target": "example.com"
}
```

---

### سيناريو 3: بدء المهمة

**Endpoint**: `POST /api/v1/missions/{mission_id}/start`

**النتيجة المتوقعة**:
```json
{
  "mission_id": "mission-...",
  "status": "running",
  "started_at": "2026-01-08T12:05:00Z"
}
```

---

### سيناريو 4: متابعة حالة المهمة

**Endpoint**: `GET /api/v1/missions/{mission_id}/status`

**النتيجة المتوقعة**:
```json
{
  "mission_id": "mission-...",
  "status": "running",
  "progress": {
    "completed_tasks": 15,
    "total_tasks": 42,
    "percentage": 35.7
  },
  "current_phase": "reconnaissance",
  "findings": [
    {
      "type": "open_port",
      "severity": "info",
      "details": "Port 80/tcp open (http)"
    }
  ]
}
```

---

## 🔍 الفحوصات الأساسية

### 1. فحص المعلومات الأساسية

```bash
curl http://208.115.230.194:8000/
```

**النتيجة**:
```json
{
  "name": "RAGLOX",
  "version": "3.0.0",
  "architecture": "Blackboard",
  "status": "operational"
}
```

---

### 2. فحص الصحة الشامل

```bash
curl http://208.115.230.194:8000/health
```

---

### 3. فحص Knowledge Base

```bash
curl http://208.115.230.194:8000/api/v1/knowledge/stats
```

**النتيجة المتوقعة**:
```json
{
  "modules": 1761,
  "techniques": 327,
  "tactics": 14,
  "nuclei_templates": 11927
}
```

---

## 🎯 Endpoints الرئيسية للاختبار

### Authentication & Users
- `POST /api/v1/auth/register` - التسجيل
- `POST /api/v1/auth/login` - تسجيل الدخول
- `POST /api/v1/auth/logout` - تسجيل الخروج
- `GET /api/v1/auth/me` - معلومات المستخدم الحالي

### Organizations
- `GET /api/v1/organizations/me` - معلومات المنظمة
- `PUT /api/v1/organizations/me` - تحديث المنظمة
- `GET /api/v1/organizations/me/users` - قائمة المستخدمين

### Missions
- `POST /api/v1/missions` - إنشاء مهمة
- `GET /api/v1/missions` - قائمة المهام
- `GET /api/v1/missions/{id}` - تفاصيل مهمة
- `POST /api/v1/missions/{id}/start` - بدء مهمة
- `POST /api/v1/missions/{id}/pause` - إيقاف مؤقت
- `POST /api/v1/missions/{id}/stop` - إيقاف نهائي
- `GET /api/v1/missions/{id}/status` - حالة المهمة
- `GET /api/v1/missions/{id}/logs` - سجلات المهمة
- `GET /api/v1/missions/{id}/report` - تقرير المهمة

### Environments
- `POST /api/v1/environments` - إنشاء بيئة
- `GET /api/v1/environments` - قائمة البيئات
- `GET /api/v1/environments/{id}` - تفاصيل بيئة
- `DELETE /api/v1/environments/{id}` - حذف بيئة
- `POST /api/v1/environments/{id}/reconnect` - إعادة الاتصال

### Knowledge Base
- `GET /api/v1/knowledge/stats` - الإحصائيات
- `GET /api/v1/knowledge/modules` - قائمة الوحدات
- `GET /api/v1/knowledge/techniques` - قائمة التقنيات
- `GET /api/v1/knowledge/tactics` - قائمة التكتيكات

---

## 📊 مقاييس الأداء المتوقعة

### زمن الاستجابة
- **Health Check**: < 50ms
- **Authentication**: < 200ms
- **Create Environment**: 5-10 seconds
- **Create Mission**: < 500ms
- **Start Mission**: < 1 second

### حدود النظام
- **Max VMs/User**: 5
- **Max Environments/User**: 10
- **Max SSH Connections**: 50
- **Max Concurrent Missions**: 5

---

## 🐛 استكشاف الأخطاء

### المشكلة: "unhealthy" Blackboard

**السبب**: Redis غير متصل

**الحل**: هذا متوقع في بيئة الاختبار. النظام يعمل في وضع In-Memory.

---

### المشكلة: "Unauthorized" Error

**السبب**: Token منتهي أو غير صالح

**الحل**:
1. سجل الدخول مرة أخرى
2. احصل على Token جديد
3. حدّث الـ Authorization في Swagger UI

---

### المشكلة: "Connection Refused" للـ VM

**السبب**: Firecracker Manager غير متاح

**الحل**: تحقق من أن الـ Manager يعمل على http://208.115.230.194:8080

```bash
curl http://208.115.230.194:8080/vms
```

---

## 📚 موارد إضافية

- **التقرير الفني الكامل**: `/opt/raglox/webapp/FIRECRACKER_INTEGRATION_REPORT.md`
- **تقرير الاختبار**: `/opt/raglox/webapp/TESTING_REPORT.md`
- **الريبو**: https://github.com/raglox/Ragloxv3
- **الوثائق**: http://208.115.230.194:8000/docs

---

## 🎉 نصائح للاختبار الفعّال

1. **استخدم Swagger UI**: أسهل طريقة للاختبار التفاعلي
2. **احفظ الـ Tokens**: ستحتاجها لجميع الطلبات المحمية
3. **راقب السجلات**: `/tmp/raglox_server.log` للتفاصيل
4. **ابدأ بسيط**: اختبر Authentication أولاً قبل الـ Missions
5. **استخدم Safety Mode**: عند اختبار المهام الحقيقية

---

**تم بنجاح ✅**  
*استمتع باختبار RAGLOX v3.0!* 🚀
