# تقرير تحليل الفجوات في التغطية - RAGLOX v3.0

## 📊 الملخص التنفيذي

**التغطية الحالية:** 34% (495/1309 سطر)  
**الهدف:** 85%+  
**الفجوة:** 51% (814 سطر إضافي مطلوب)

---

## 🎯 الملفات المستهدفة

### 1. `src/api/auth_routes.py`
- **التغطية الحالية:** 46% (217/418 سطر)
- **الهدف:** 85%+
- **الفجوة:** 201 سطر

### 2. `src/controller/mission.py`
- **التغطية الحالية:** 27% (219/756 سطر)
- **الهدف:** 85%+
- **الفجوة:** 537 سطر

### 3. `src/core/database/user_repository.py`
- **التغطية الحالية:** 39% (59/135 سطر)
- **الهدف:** 85%+
- **الفجوة:** 76 سطر

---

## 📋 التحليل التفصيلي

## 1. تحليل `src/api/auth_routes.py` (1159 سطر)

### 1.1 الدوال المختبرة حالياً (4 دوال)
1. ✅ [`register()`](src/api/auth_routes.py:549) - مختبرة جزئياً في `test_auth_lazy_provisioning.py`
2. ✅ [`provision_user_vm()`](src/api/auth_routes.py:417) - مختبرة في `test_auth_lazy_provisioning.py`
3. ✅ [`get_vm_status()`](src/api/auth_routes.py:900) - مختبرة في `test_auth_lazy_provisioning.py`
4. ✅ [`reprovision_vm()`](src/api/auth_routes.py:935) - مختبرة في `test_auth_lazy_provisioning.py`

### 1.2 الدوال غير المختبرة (20 دالة)

#### أولوية عالية (Critical) - 8 دوال

| # | الدالة | السطر | المعاملات | التبعيات | حالات الاختبار المطلوبة |
|---|--------|------|-----------|----------|------------------------|
| 1 | [`login()`](src/api/auth_routes.py:682) | 682 | `request`, `data: LoginRequest` | `UserRepository`, `TokenStore`, `OrganizationRepository` | - نجاح تسجيل الدخول<br>- كلمة مرور خاطئة<br>- حساب مقفل<br>- حساب معطل<br>- remember_me=True<br>- محاولات فاشلة متعددة |
| 2 | [`logout()`](src/api/auth_routes.py:765) | 765 | `request`, `credentials`, `user` | `TokenStore` | - نجاح تسجيل الخروج<br>- إلغاء التوكن<br>- بدون توكن |
| 3 | [`get_current_user_info()`](src/api/auth_routes.py:784) | 784 | `request`, `user` | `OrganizationRepository` | - نجاح الحصول على المعلومات<br>- مع بيانات VM<br>- بدون بيانات VM |
| 4 | [`update_profile()`](src/api/auth_routes.py:811) | 811 | `request`, `updates`, `user` | `UserRepository`, `OrganizationRepository` | - تحديث الاسم<br>- بيانات فارغة<br>- بيانات غير صالحة |
| 5 | [`change_password()`](src/api/auth_routes.py:855) | 855 | `request`, `data`, `user` | `UserRepository`, `TokenStore` | - نجاح تغيير كلمة المرور<br>- كلمة مرور حالية خاطئة<br>- كلمة مرور ضعيفة<br>- إلغاء جميع التوكنات |
| 6 | [`get_current_user()`](src/api/auth_routes.py:276) | 276 | `request`, `credentials` | `TokenStore`, `UserRepository` | - توكن صالح<br>- توكن منتهي<br>- توكن ملغى<br>- توكن غير صالح<br>- حساب معطل |
| 7 | [`create_access_token()`](src/api/auth_routes.py:214) | 214 | `user_id`, `organization_id`, `token_store`, `expires_hours` | `TokenStore`, `Settings` | - إنشاء توكن عادي<br>- توكن ممتد (remember_me)<br>- تخزين في Redis |
| 8 | [`decode_token()`](src/api/auth_routes.py:257) | 257 | `token` | `Settings` | - فك تشفير توكن صالح<br>- توكن منتهي<br>- توكن غير صالح |

#### أولوية متوسطة (Medium) - 8 دوال

| # | الدالة | السطر | المعاملات | التبعيات | حالات الاختبار المطلوبة |
|---|--------|------|-----------|----------|------------------------|
| 9 | [`list_organization_users()`](src/api/auth_routes.py:979) | 979 | `request`, `user` | `UserRepository`, `OrganizationRepository` | - قائمة المستخدمين<br>- منظمة فارغة<br>- صلاحيات admin |
| 10 | [`update_user_status()`](src/api/auth_routes.py:1016) | 1016 | `request`, `user_id`, `new_status`, `admin` | `UserRepository`, `TokenStore` | - تعطيل مستخدم<br>- تفعيل مستخدم<br>- منع تعطيل الذات<br>- إلغاء التوكنات |
| 11 | [`update_user_role()`](src/api/auth_routes.py:1057) | 1057 | `request`, `user_id`, `new_role`, `admin` | `UserRepository` | - تغيير الدور<br>- دور غير صالح<br>- مستخدم غير موجود |
| 12 | [`get_organization_info()`](src/api/auth_routes.py:1096) | 1096 | `request`, `user` | `OrganizationRepository` | - معلومات المنظمة<br>- منظمة غير موجودة |
| 13 | [`invite_user_to_organization()`](src/api/auth_routes.py:1121) | 1121 | `request`, `email`, `role`, `admin` | `OrganizationRepository`, `UserRepository` | - إنشاء دعوة<br>- مستخدم موجود<br>- إنشاء كود دعوة |
| 14 | [`get_optional_user()`](src/api/auth_routes.py:367) | 367 | `request`, `credentials` | - | - مع توكن<br>- بدون توكن<br>- توكن غير صالح |
| 15 | [`require_role()`](src/api/auth_routes.py:381) | 381 | `*roles` | - | - دور صحيح<br>- دور خاطئ<br>- أدوار متعددة |
| 16 | [`require_org_owner()`](src/api/auth_routes.py:397) | 397 | - | - | - مالك المنظمة<br>- مستخدم عادي<br>- superuser |

#### أولوية منخفضة (Low) - 4 دوال

| # | الدالة | السطر | الوصف | حالات الاختبار |
|---|--------|------|-------|----------------|
| 17 | [`get_user_repo()`](src/api/auth_routes.py:174) | 174 | Helper function | - نجاح<br>- خدمة غير متاحة |
| 18 | [`get_org_repo()`](src/api/auth_routes.py:185) | 185 | Helper function | - نجاح<br>- خدمة غير متاحة |
| 19 | [`get_token_store_from_request()`](src/api/auth_routes.py:196) | 196 | Helper function | - من app.state<br>- من global<br>- غير متاح |
| 20 | [`_get_vm_status_message()`](src/api/auth_routes.py:918) | 918 | Helper function | - جميع حالات VM |

### 1.3 الفروع غير المغطاة

#### في [`register()`](src/api/auth_routes.py:549):
- ✅ السطر 569-574: التحقق من البريد الإلكتروني الموجود
- ❌ السطر 581-594: الانضمام عبر كود دعوة
- ❌ السطر 596-610: إنشاء منظمة جديدة
- ✅ السطر 612-626: إنشاء منظمة شخصية

#### في [`login()`](src/api/auth_routes.py:682):
- ❌ السطر 700-705: التحقق من الحساب المقفل
- ❌ السطر 707-718: التحقق من كلمة المرور
- ❌ السطر 720-725: التحقق من حالة الحساب
- ❌ السطر 736-742: remember_me logic

#### في [`change_password()`](src/api/auth_routes.py:855):
- ❌ السطر 879-884: التحقق من كلمة المرور الحالية
- ❌ السطر 893: إلغاء جميع التوكنات

### 1.4 معالجة الأخطاء غير المغطاة

| الدالة | نوع الخطأ | السطر | الحالة |
|--------|----------|------|--------|
| [`register()`](src/api/auth_routes.py:549) | `HTTPException(409)` | 571 | ❌ غير مختبر |
| [`register()`](src/api/auth_routes.py:549) | `HTTPException(400)` | 585 | ❌ غير مختبر |
| [`login()`](src/api/auth_routes.py:682) | `HTTPException(401)` | 695 | ❌ غير مختبر |
| [`login()`](src/api/auth_routes.py:682) | `HTTPException(423)` | 702 | ❌ غير مختبر |
| [`login()`](src/api/auth_routes.py:682) | `HTTPException(403)` | 722 | ❌ غير مختبر |
| [`get_current_user()`](src/api/auth_routes.py:276) | `HTTPException(401)` | 286 | ❌ غير مختبر |
| [`get_current_user()`](src/api/auth_routes.py:276) | `HTTPException(503)` | 297 | ❌ غير مختبر |
| [`change_password()`](src/api/auth_routes.py:855) | `HTTPException(404)` | 874 | ❌ غير مختبر |
| [`change_password()`](src/api/auth_routes.py:855) | `HTTPException(401)` | 881 | ❌ غير مختبر |

---

## 2. تحليل `src/controller/mission.py` (2083 سطر)

### 2.1 الدوال المختبرة حالياً (1 دالة)
1. ✅ [`_execute_shell_command()`](src/controller/mission.py:1628) - مختبرة في `test_mission_lazy_execution.py`

### 2.2 الدوال غير المختبرة (30+ دالة)

#### أولوية عالية (Critical) - 10 دوال

| # | الدالة | السطر | المعاملات | التبعيات | حالات الاختبار المطلوبة |
|---|--------|------|-----------|----------|------------------------|
| 1 | [`create_mission()`](src/controller/mission.py:161) | 161 | `mission_data`, `organization_id`, `created_by` | `Blackboard` | - إنشاء مهمة<br>- مع organization_id<br>- بدون organization_id<br>- أهداف متعددة |
| 2 | [`start_mission()`](src/controller/mission.py:222) | 222 | `mission_id` | `Blackboard`, `SessionManager`, `StatsManager` | - بدء مهمة<br>- مهمة غير موجودة<br>- حالة خاطئة<br>- بدء المتخصصين |
| 3 | [`pause_mission()`](src/controller/mission.py:295) | 295 | `mission_id` | `Blackboard` | - إيقاف مهمة<br>- مهمة غير قيد التشغيل |
| 4 | [`resume_mission()`](src/controller/mission.py:327) | 327 | `mission_id` | `Blackboard` | - استئناف مهمة<br>- مهمة غير متوقفة |
| 5 | [`stop_mission()`](src/controller/mission.py:359) | 359 | `mission_id` | `Blackboard`, `SessionManager`, `StatsManager` | - إيقاف مهمة<br>- تنظيف المتخصصين<br>- إيقاف المديرين |
| 6 | [`get_mission_status()`](src/controller/mission.py:414) | 414 | `mission_id` | `Blackboard` | - من Redis<br>- من الذاكرة المحلية<br>- مهمة غير موجودة |
| 7 | [`request_approval()`](src/controller/mission.py:875) | 875 | `mission_id`, `action` | `ApprovalStore`, `Blackboard` | - طلب موافقة<br>- حفظ في Redis<br>- نشر