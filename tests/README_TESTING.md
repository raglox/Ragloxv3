# RAGLOX v3.0 - Test Suite Guide

## 📋 Overview

مجموعة الاختبارات الشاملة لـ RAGLOX v3.0 تغطي:
- ✅ Integration Tests (94 tests)
- ✅ E2E Tests (6 tests)  
- ✅ Unit Tests
- ⚠️ API Tests (تحتاج PostgreSQL)
- ⚠️ Real Integration Tests (تحتاج بنية تحتية فعلية)
- ⚠️ Production Tests (تحتاج خدمات خارجية)

---

## 🚀 تشغيل الاختبارات

### 1. تشغيل جميع الاختبارات الأساسية (Integration + E2E)
```bash
pytest tests/integration tests/e2e
```
**النتيجة المتوقعة**: 94 passed, 2 skipped

### 2. تشغيل جميع الاختبارات (بدون API/DB tests)
```bash
pytest tests/ --ignore=tests/api_suite --ignore=tests/real_integration --ignore=tests/production
```

### 3. تشغيل اختبارات Phase 3.5 فقط
```bash
pytest tests/integration/test_vector_knowledge.py tests/integration/test_hybrid_retriever.py tests/e2e/test_hybrid_rag_e2e.py -v
```

### 4. تشغيل مع coverage للملفات الجديدة
```bash
pytest tests/integration/test_vector_knowledge.py tests/integration/test_hybrid_retriever.py \
       --cov=src.core.vector_knowledge --cov=src.core.hybrid_retriever \
       --cov-report=html --cov-report=term-missing
```

---

## 📊 نتائج التغطية المتوقعة

| Module | Coverage | Status |
|--------|----------|--------|
| `src.core.hybrid_retriever.py` | **91%** | ✅ Excellent |
| `src.core.vector_knowledge.py` | **72%** | ⚠️ Good |
| Overall Phase 3.5 | **~82%** | ✅ Above target |

---

## 📁 هيكل الاختبارات

```
tests/
├── integration/          # Integration tests (94 tests)
│   ├── test_vector_knowledge.py        (26 tests) ✅
│   ├── test_hybrid_retriever.py        (22 tests) ✅
│   ├── test_tactical_reasoning_integration.py (11 tests) ✅
│   ├── test_deepseek_integration.py    (9 tests) ✅
│   ├── test_new_tools.py              (15 tests) ✅
│   └── test_hitl_flow.py              (1 test) ✅
│
├── e2e/                 # End-to-end tests (6 tests)
│   └── test_hybrid_rag_e2e.py         (6 tests) ✅
│
├── unit/                # Unit tests
│
├── api_suite/           # API tests (تحتاج PostgreSQL)
│
├── real_integration/    # Real infrastructure tests
│
├── production/          # Production chaos tests
│
└── conftest.py          # Shared fixtures
```

---

## 🎯 الاختبارات حسب الـ Markers

### تشغيل اختبارات محددة
```bash
# Integration tests only
pytest -m integration

# E2E tests only  
pytest -m e2e

# Fast tests only (< 100ms)
pytest -m fast

# Exclude slow tests
pytest -m "not slow"

# Integration but not database tests
pytest -m "integration and not db"
```

---

## ⚙️ متطلبات الاختبارات

### الاختبارات الأساسية (Integration + E2E)
✅ **لا تحتاج أي متطلبات خارجية** - تعمل مباشرة مع mocks

**المتطلبات**:
- Python 3.10+
- Dependencies: `pip install -r requirements.txt`
- Vector dependencies: `pip install sentence-transformers faiss-cpu`

### اختبارات API
⚠️ تحتاج:
- PostgreSQL running on localhost:5432
- Redis running on localhost:6379
- Database schema initialized

```bash
# Start services
docker-compose up -d postgres redis

# Run API tests
pytest tests/api_suite/
```

### اختبارات Real Integration
⚠️ تحتاج:
- SSH access to target machines
- Real vulnerability scanning tools (Nuclei)
- Network connectivity

### اختبارات Production
⚠️ تحتاج:
- Full infrastructure setup
- External services (OpenAI API, etc.)

---

## 🔧 أوامر مفيدة

### تشغيل سريع (بدون تفاصيل)
```bash
pytest -q
```

### إيقاف عند أول فشل
```bash
pytest -x
```

### إيقاف بعد 3 أخطاء
```bash
pytest --maxfail=3
```

### تشغيل متوازي (أسرع)
```bash
pytest -n auto  # requires: pip install pytest-xdist
```

### تشغيل اختبار محدد
```bash
pytest tests/integration/test_vector_knowledge.py::TestVectorKnowledgeStore::test_initialization_success
```

### تشغيل الاختبارات التي تحتوي على كلمة معينة
```bash
pytest -k "vector"
pytest -k "hybrid"
pytest -k "initialization"
```

### عرض جميع الاختبارات المتاحة
```bash
pytest --collect-only
```

### عرض تفاصيل أكثر
```bash
pytest -vv --tb=long
```

---

## 📈 تقرير Coverage

### إنشاء تقرير HTML
```bash
pytest --cov=src --cov-report=html
# ثم افتح: htmlcov/index.html
```

### إنشاء تقرير JSON
```bash
pytest --cov=src --cov-report=json
# النتيجة في: coverage.json
```

### إنشاء تقرير Terminal
```bash
pytest --cov=src --cov-report=term-missing
```

---

## 🐛 استكشاف الأخطاء

### الاختبار يفشل بسبب Import Error
```bash
# تأكد من تثبيت جميع المكتبات
pip install -r requirements.txt
pip install sentence-transformers faiss-cpu
```

### الاختبار يفشل بسبب Database Error
```bash
# تجاهل اختبارات API
pytest --ignore=tests/api_suite
```

### الاختبار بطيء جداً
```bash
# استبعد الاختبارات البطيئة
pytest -m "not slow"

# أو استخدم تشغيل متوازي
pytest -n auto
```

---

## ✅ قائمة التحقق قبل Commit

- [ ] جميع اختبارات Integration تعمل: `pytest tests/integration/`
- [ ] جميع اختبارات E2E تعمل: `pytest tests/e2e/`
- [ ] Coverage > 70% للملفات الجديدة
- [ ] لا توجد warnings خطيرة
- [ ] كل الاختبارات الجديدة موثقة بشكل جيد

---

## 📞 الدعم

إذا واجهت أي مشاكل:
1. تحقق من `.env.test` للإعدادات الصحيحة
2. تأكد من تثبيت جميع المكتبات
3. راجع هذا الملف للاستخدام الصحيح
4. تحقق من logs في `pytest.log`

---

**آخر تحديث**: 2026-01-09  
**الإصدار**: Phase 3.5 Complete  
**الحالة**: ✅ جاهز للإنتاج
