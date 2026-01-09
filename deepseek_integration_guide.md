



# دليل تكامل DeepSeek مع RAGLOX

**المؤلف**: Manus AI
**التاريخ**: 2026-01-09

## 1. الملخص التنفيذي

هذه الوثيقة تقدم دليلاً شاملاً لتكامل DeepSeek API مع وكيل RAGLOX الحالي. الهدف هو الاستفادة من قدرات DeepSeek المتقدمة (مثل Thinking Mode و Strict Mode) وأسعاره التنافسية لتعزيز أداء الوكيل وتقديم تجربة مستخدم احترافية.

### التوصية الرئيسية

**استخدم DeepSeek كـ LLM أساسي أو كخيار إضافي في RAGLOX**، مع الاستفادة من توافقه الكامل مع OpenAI SDK لتقليل جهد التكامل.

| الميزة | الفائدة لـ RAGLOX |
|---|---|
| **Thinking Mode** | الوكيل يفكر قبل اختيار الأداة، مما يزيد من دقة القرارات |
| **Strict Mode** | يضمن JSON صحيح دائماً، مما يقلل أخطاء تحليل الردود |
| **OpenAI Compatible** | سهولة التكامل مع الكود الموجود |
| **أسعار أقل** | توفير كبير في التكاليف (10-50x أرخص من GPT-4) |

---

## 2. تحليل الكود الحالي

وكيل RAGLOX الحالي (`HackerAgent`) مبني على بنية ReAct (Reasoning + Acting) ويستخدم `openai_provider.py` للتواصل مع OpenAI. هذا يعني أن التكامل مع DeepSeek سيكون سهلاً للغاية.

### نقاط التكامل الرئيسية:

| الملف | الدالة/الكلاس | الغرض |
|---|---|---|
| `openai_provider.py` | `OpenAIProvider` | الكلاس المسؤول عن التواصل مع OpenAI |
| `hacker_agent.py` | `_get_llm_response` | الحصول على رد من LLM |
| `hacker_agent.py` | `_stream_llm_response` | الحصول على رد متدفق من LLM |
| `llm/service.py` | `LLMService` | الخدمة المركزية التي تدير LLM providers |

---

## 3. خطة التكامل (3 خطوات)

### الخطوة 1: إنشاء `DeepSeekProvider`

**الهدف**: إنشاء provider جديد لـ DeepSeek بنفس بنية `OpenAIProvider`.

1. **إنشاء ملف `deepseek_provider.py`**: انسخ `openai_provider.py` وقم بتغيير اسم الكلاس إلى `DeepSeekProvider`.

2. **تغيير `base_url`**: غير `DEFAULT_BASE_URL` إلى `https://api.deepseek.com`.

3. **تحديث `available_models`**: أضف `deepseek-chat` و `deepseek-reasoner`.

4. **تعديل `_build_request`**: أضف `extra_body` لتفعيل Thinking Mode:
   ```python
   # في deepseek_provider.py -> _build_request
   if kwargs.get("thinking_mode"):
       request["extra_body"] = {"thinking": {"type": "enabled"}}
       request["model"] = "deepseek-reasoner" # أو deepseek-chat
   ```

### الخطوة 2: تحديث `LLMService`

**الهدف**: جعل `LLMService` قادراً على استخدام `DeepSeekProvider`.

1. **في `llm/service.py`**: أضف `DeepSeekProvider` إلى قائمة الـ providers.

2. **في `config.yml`**: أضف إعدادات DeepSeek:
   ```yaml
   llm:
     default_provider: deepseek
     providers:
       openai:
         api_key: "sk-..."
         model: "gpt-4o"
       deepseek:
         api_key: "sk-acd73fdc50804178b3f1a9fb68ee1390"
         model: "deepseek-chat"
         thinking_mode: true # تفعيل Thinking Mode
   ```

### الخطوة 3: تحديث `HackerAgent` للاستفادة من Thinking Mode

**الهدف**: جعل الوكيل يفهم `reasoning_content` ويقدمه للمستخدم.

1. **في `hacker_agent.py` -> `_stream_llm_response`**: ابحث عن `chunk` وقم بتعديلها لتعالج `reasoning_content`:
   ```python
   # في _stream_llm_response
   async for chunk in llm.stream_generate(messages):
       if hasattr(chunk, 'reasoning_content') and chunk.reasoning_content:
           yield {"type": "thinking", "content": chunk.reasoning_content}
       
       if hasattr(chunk, 'content') and chunk.content:
           yield {"type": "text", "content": chunk.content}
       
       if hasattr(chunk, 'tool_calls') and chunk.tool_calls:
           # ... (نفس الكود الحالي)
   ```

---

## 4. تقديم تجربة احترافية داخل الدردشة

**الهدف**: عرض `reasoning_content` للمستخدم بطريقة احترافية.

### توصيات الواجهة الأمامية (Frontend):

1. **مكون `Thinking` جديد**: أنشئ مكون React جديداً لعرض `reasoning_content`.
   - استخدم أيقونة 🧠 أو 💭
   - استخدم لوناً مختلفاً (مثل الرمادي الفاتح)
   - اجعله قابلاً للطي (collapsible) للمحادثات الطويلة

2. **تحديث `AIChatPanel.tsx`**: في `handleWebSocketMessage`، ابحث عن `type === "thinking"` وقم بعرض المكون الجديد.

3. **Streaming للـ `reasoning_content`**: إذا كان `reasoning_content` طويلاً، قم بعرضه كلمة بكلمة بنفس طريقة عرض الردود العادية.

### مثال على الواجهة:

```
[You]
Scan 192.168.1.1

[RAGLOX]
🧠 Thinking...
- The user wants to scan a target.
- The best tool for this is nmap_scan.
- I will use the 'quick' scan type for speed.

[RAGLOX] (Tool Call)
Running nmap_scan(target="192.168.1.1", scan_type="quick")

[RAGLOX] (Tool Result)
Open ports: 22, 80, 443

[RAGLOX]
I found 3 open ports: 22 (SSH), 80 (HTTP), and 443 (HTTPS). I recommend we investigate the web server on port 80 next.
```

---

## 5. الخلاصة

بتطبيق هذه الخطوات، يمكنك تكامل DeepSeek مع RAGLOX بشكل كامل، والاستفادة من ميزاته المتقدمة لتقديم وكيل اختراق أكثر ذكاءً واحترافية، مع توفير كبير في التكاليف.

### المراجع

1. [DeepSeek API Documentation](https://api-docs.deepseek.com)
2. [RAGLOX Source Code](https://github.com/raglox/Ragloxv3)
