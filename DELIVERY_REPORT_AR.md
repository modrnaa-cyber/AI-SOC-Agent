# تقرير التسليم — إضافة Security Alert Analyzer
**المطوّر:** Azzam Abdulkarim Alharbi
**التاريخ:** 2026-10-10
**المشروع الأساسي:** https://github.com/M507/AI-SOC-Agent (SamiGPT — MIT)

---

## 1. حالة السيرفر قبل وبعد العمل

### قبل

| العنصر | القيمة |
|---|---|
| نظام التشغيل | **Debian GNU/Linux 13 (trixie)** — وليس Ubuntu كما طُلب |
| المعالج | Intel Core i5-10210U، 8 خيوط |
| الذاكرة | 7.5 GiB إجمالي، 5.7 GiB متاح |
| المساحة | 233 GB إجمالي، 202 GB متاح (9% مستخدم) |
| Git | 2.47.3 |
| Docker | **غير متوفر** — لا يوجد Docker daemon ولا صلاحية docker group |
| Docker Compose | غير متوفر |
| GitHub CLI | غير مثبت |
| Python | 3.11.15 |

### بعد

| العنصر | التغيير |
|---|---|
| المشروع | منزّل في `~/cyber-lab/AI-SOC-Agent` |
| اعتماديات Python | مثبتة من `requirements.txt` (fastapi, uvicorn, cryptography, argon2-cffi, ...) |
| GitHub CLI | مثبت (2.46.0) ومصادَق كحساب `modrnaa-cyber` |
| التطبيق | **يعمل** على `https://127.0.0.1:18081` |
| الإضافة | منشأة ومختبرة — 30 اختبارًا ناجحًا |
| الفرع | `feat/security-alert-analyzer` مع commit واحد محلي |

### انحرافات عن التعليمات — بصراحة

1. **النظام Debian 13 وليس Ubuntu.** تعليمات المشروع تفترض Ubuntu. التطبيق عمل مباشرة على Debian دون تعديل.
2. **Docker غير متوفر في هذه البيئة.** لذلك **لم أستخدم Docker Compose** كما طُلب في المرحلة 3. بدلًا من ذلك شغّلت التطبيق مباشرة بـ Python مع ربط على `127.0.0.1` فقط. لم أستطع اختبار مسار `onboarding/docker-compose.yml`.
3. **البيئة معزولة أصلًا** (حاوية Docker مستقلة)، وهذا يحقق شرط "مختبر مستقل عن الخدمات الشخصية".

### ما لم أغيّره التزامًا بالتعليمات

- لم أوقف أي خدمة قائمة.
- لم أغيّر إعدادات Hermes Agent أو الشبكة أو الجدار الناري.
- لم أفتح أي منفذ عام — الربط على `127.0.0.1` فقط.
- لم أضف أي سر أو مفتاح API في الكود أو Git.
- لم أنشئ مستودعًا عامًا، ولم أنفّذ `push`، ولم أغيّر صلاحيات أي مستودع.

---

## 2. الملفات التي فحصتها وعدّلتها أو أنشأتها

### فُحصت (قراءة فقط)

- `README.md`, `LICENSE`, `requirements.txt`, `.gitignore`
- `app.py` — نقطة الدخول، وسائط CLI، منطق الإعداد
- `config.json.example` — كل الأقسام (thehive, iris, elastic, edr, cti, netbox, ai_controller, llm, mcp, web)
- `onboarding/docker-compose.yml` + `onboarding/Dockerfile` + `onboarding/run.sh`
- `servee/install.sh` + `servee/servee.service` — تثبيت كخدمة systemd على `/opt/servee`
- `src/core/tls.py`, `src/core/config_storage.py`, `src/core/dto.py`
- `src/ai_controller/web/server.py`, `auth.py`, `routes_detections.py`
- `src/ai_controller/detection/` — حزمة Detection as Code (rules_store, settings, validation, errors)
- `src/mcp/rules_engine.py`
- `tests/` — 43 ملف اختبار قائم

### أُنشئت (كلها جديدة — لا ملف أصلي عُدّل)

| الملف | الوصف |
|---|---|
| `src/security_alert_analyzer/__init__.py` | الواجهة العامة للحزمة |
| `src/security_alert_analyzer/schema.py` | التحقق الصارم من مخطط التنبيهات |
| `src/security_alert_analyzer/severity.py` | تصنيف الخطورة بقواعد قابلة للتفسير |
| `src/security_alert_analyzer/report.py` | إخراج JSON وMarkdown |
| `src/security_alert_analyzer/__main__.py` | نقطة دخول CLI |
| `src/security_alert_analyzer/examples/sample_alerts.json` | 5 تنبيهات اصطناعية تغطي كل الدرجات |
| `src/security_alert_analyzer/examples/invalid_alert.json` | تنبيه غير صالح للعرض |
| `src/security_alert_analyzer/examples/README.md` | شرح البيانات التجريبية |
| `tests/security_alert_analyzer/test_schema.py` | 9 اختبارات تحقق |
| `tests/security_alert_analyzer/test_severity.py` | 8 اختبارات تصنيف |
| `tests/security_alert_analyzer/test_report.py` | 5 اختبارات تقارير |
| `tests/security_alert_analyzer/test_cli.py` | 8 اختبارات CLI وحالات حدية |
| `docs/security-alert-analyzer.md` | توثيق كامل للإضافة |
| `SECURITY.md` | نطاق الأداة والإبلاغ عن الثغرات |
| `CONTRIBUTIONS.md` | وصف المساهمة بدقة |

### عُدّلت (ملف واحد فقط)

| الملف | التغيير |
|---|---|
| `README.md` | أُضيف قسم `Author Contributions` فقط. **لم يُحذف أو يُغيَّر أي محتوى أصلي.** |

---

## 3. خطوات التشغيل الفعلية

```bash
# 1. تنزيل المشروع
mkdir -p ~/cyber-lab && cd ~/cyber-lab
git clone https://github.com/M507/AI-SOC-Agent.git

# 2. تثبيت الاعتماديات (لا Docker متوفر في هذه البيئة)
cd ~/cyber-lab/AI-SOC-Agent
pip3 install -r requirements.txt

# 3. تجهيز الإعداد وملفات التشغيل
cp config.json.example config.json
mkdir -p logs data/ai_controller

# 4. التشغيل محليًا فقط (لا منافذ عامة)
python3 app.py --host 127.0.0.1 --port 18081 --no-mcp

# 5. التحقق من الصحة
curl -sk https://127.0.0.1:18081/api/setup/status
# → {"success":true,"setup_required":true,"completed":false,"resume_step":"welcome"} [HTTP 200]
```

**تشغيل الإضافة:**

```bash
# تقرير بصيغتي JSON وMarkdown
python3 -m src.security_alert_analyzer \
    src/security_alert_analyzer/examples/sample_alerts.json \
    --json-out report.json --md-out report.md

# تشغيل الاختبارات
python3 -m pytest tests/security_alert_analyzer/ -v
```

---

## 4. الاختبارات: ما اجتاز وما لم يجتز

### إضافة Security Alert Analyzer — **كلها ناجحة**

```
$ python3 -m pytest tests/security_alert_analyzer/ -q
30 passed in 0.04s
```

تغطي: المسار الناجح، المدخلات غير الصالحة، والحالات الحدية (حقول ناقصة، تواريخ سيئة، مفاتيح مجهولة، IP غير صالح، غلاف `{"alerts":[...]}`، ملف مفقود، JSON غير صالح، مجلد إخراج غير موجود).

### التحقق الفعلي من CLI

```
$ python3 -m src.security_alert_analyzer .../sample_alerts.json --json-out /tmp/report.json
LAB-0001: informational (score 0)
LAB-0002: medium (score 35)
LAB-0003: high (score 50)
LAB-0004: critical (score 100)
LAB-0005: informational (score 0)
exit=0

$ python3 -m src.security_alert_analyzer .../invalid_alert.json --json-out /tmp/bad.json
error: Field 'timestamp' must be an ISO 8601 datetime, got 'not-a-date'.
exit=2
```

### اختبارات المشروع الأصلي — **لم تُكسر**

| | ناجح | فاشل | متخطى | أخطاء |
|---|---|---|---|---|
| قبل تغييراتي (استنساخ نظيف) | 312 | **27** | 5 | 2 |
| بعد تغييراتي | **342** | **27** | 5 | 2 |

الفرق: **+30 ناجح** بالضبط (اختبارات إضافتي)، و**نفس الـ27 فشل** لم تتغير.

**إثبات أن الـ27 ليست من عملي:** شُغّلت المجموعة على استنساخ نظيف من المستودع الأصلي بلا أي تعديل → **نفس الـ27 فشل بالضبط**. هي مشكلات موجودة مسبقًا في المشروع الأصلي (انحراف إصدارات اعتماديات في تجهيزات اختبارات الويب/المصادقة)، وخارج نطاق إضافتي، وتركتها دون مساس.

---

## 5. المشكلات المتبقية

1. **Docker غير متوفر** في هذه البيئة → مسار `onboarding/docker-compose.yml` لم يُختبر. يحتاج تنفيذه على جهاز فيه Docker daemon.
2. **27 فشل مسبق في اختبارات المشروع الأصلي** — لم أُصلحها (خارج نطاق الإضافة). هي مسألة اعتماديات لدى المشروع الأصلي.
3. **لم أختبر أي تكامل خارجي** (Elastic, TheHive, IRIS, Velociraptor, NetBox, LLM) — بموجب تعليماتك بعدم إرسال بيانات خارجية دون موافقة. الإضافة نفسها لا تحتاج أي منها.
4. **لم أُنشئ Fork ولم أدفع** — بانتظار موافقتك الصريحة.
5. **رمز GitHub الذي أرسلته أصبح مكشوفًا في المحادثة** → يجب إبطاله (revoke) من إعدادات GitHub بعد الانتهاء.

---

## 6. العنوان المقترح ورابط المصدر

**العنوان المقترح للمشروع:**
> **Security Alert Analyzer — Explainable Triage Add-on for SamiGPT**
> إضافة تحليل التنبيهات الأمنية: تحقق صارم، تصنيف خطورة قابل للتفسير، وتقارير منظمة

**المصدر الأصلي:** https://github.com/M507/AI-SOC-Agent — المؤلف **M507** — رخصة **MIT**

---

## 7. مساهمتي الأصلية بدقة

**بنيت:** حزمة Python مستقلة `src/security_alert_analyzer/` (4 وحدات) + 30 اختبارًا + 4 ملفات توثيق + بيانات تجريبية اصطناعية.

**ما فعلته تحديدًا:**
1. **تحقق صارم من المخطط** — يرفض الحقول الناقصة، الفارغة، المفاتيح المجهولة، التواريخ غير الصالحة، وعناوين IP غير الصحيحة، مع سبب واضح ورمز خروج غير صفري.
2. **تصنيف خطورة قابل للتفسير** — قواعد شفافة بأوزان ثابتة (حساب متميز +50، وجهة عامة +20، منفذ مشبوه +15، مؤشر معروف +100)، وكل تصنيف يعيد **قائمة الأسباب المرتبة** التي أنتجته. لا صندوق أسود.
3. **تقرير بصيغتين** — JSON للآلات وMarkdown للبشر، وكلاهما يحمل تنبيهًا صريحًا عن الإيجابيات والسلبيات الكاذبة داخل التقرير نفسه.
4. **اختبارات آلية** — 30 اختبارًا بنهج TDD (اختبار فاشل أولًا، ثم التنفيذ). ظهر خلال التطوير فشلان حقيقيان أُصلحا: استخدام عنوان RFC 5737 كـ"خارجي" (صُحّح إلى `is_global`)، ورفض غلاف `{"alerts":[...]}`.
5. **توثيق كامل** — `docs/`, `SECURITY.md`, `CONTRIBUTIONS.md`, وقسم في `README.md`.

**ما لم أفعله (ولن أدّعيه):**
- لم أبنِ المنصة الأصلية SamiGPT.
- **لا استخدام لأي LLM** — التصنيف قواعد ثابتة، لا نموذج ولا استدلال.
- **لا تكامل مع SIEM** — لا استعلام لـ Elastic أو غيره، ولا اتصال شبكي إطلاقًا.
- **لا إجراء استجابة تلقائية** — لا عزل جهاز ولا تعطيل حساب.
- **لا أرقام أداء ولا شهادات نجاح** — لم أقِس أي شيء، فلا أدّعي شيئًا.
- لم أُصلح الـ27 فشلًا المسبقًا في المشروع الأصلي.

**الترخيص والإسناد:** المساهمة تحت نفس رخصة **MIT**، وإشعار حقوق النشر الأصلي في `LICENSE` محفوظ بالكامل. لم أُغيّر أسماء المؤلفين الأصليين ولا حذفت سجلهم.
