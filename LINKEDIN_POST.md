# LinkedIn Post — based only on work actually done

## English

---

I built a small, focused security add-on and I want to describe it honestly.

The platform is **SamiGPT** (AI-SOC-Agent), an open-source security
investigation and incident response project by **M507** — released under the
MIT License. I did **not** build that platform. I studied it, ran it, and
contributed an independent add-on to it.

**What I built: the Security Alert Analyzer.**

It takes JSON security alerts, validates them against a documented schema,
classifies severity with an **explainable rule set**, and produces a structured
report in JSON and Markdown.

What makes it worth writing about is what it deliberately *refuses* to do:

- It does **not** use an LLM. Severity comes from transparent rules with fixed
  weights, and every verdict returns the ordered list of reasons that produced
  the score. No black box.
- It does **not** query a SIEM or open a network connection. It reads a local
  file and writes a local report.
- It does **not** take an automatic action. It never isolates a host or
  disables an account — a human reads the report and decides.
- It carries its own **false-positive and false-negative warning inside every
  report**, so nobody can consume a verdict without seeing the caveat.

**How it was built:** test-first. I wrote a failing test, watched it fail, then
implemented. That surfaced two real bugs I had to fix rather than hide — a test
that wrongly treated an RFC 5737 documentation address as external egress, and
a CLI that rejected the common `{"alerts": [...]}` feed format.

**What I verified, with real commands:**

- 30 tests pass — success path, invalid input, and edge cases (missing fields,
  malformed timestamps, unknown keys, bad IPs, unreadable input, unwritable
  output).
- The command-line tool scores a synthetic five-alert feed across the full
  range from `informational` to `critical`, and rejects a malformed alert with
  a non-zero exit code.
- The original project's test suite is unchanged by my work: 27 pre-existing
  failures before and 27 after, confirmed against a clean clone. My work adds
  30 passing tests and breaks nothing.

**What I am not claiming:** no performance numbers, no accuracy benchmarks, no
"success stories." None were measured, so none are stated. The tool is triage
input, not a conclusion.

Full source, tests, and documentation are in the repository. Attribution to the
original author is preserved, and the MIT License is unchanged.

Grateful to M507 for releasing the platform openly — reading real production
SOC code taught me more than any tutorial.

#CyberSecurity #SOC #DetectionEngineering #BlueTeam #Python #OpenSource #TDD

---

## العربية

---

بنيت إضافة أمنية صغيرة ومركّزة، وأريد وصفها بصدق.

المنصة هي **SamiGPT** (AI-SOC-Agent)، مشروع مفتوح المصدر للتحقيق في الحوادث
والاستجابة الأمنية من تطوير **M507**، منشور تحت رخصة MIT. **لم أبنِ تلك
المنصة.** درستها، وشغّلتها، وقدّمت لها إضافة مستقلة.

**ما بنيته: مُحلّل التنبيهات الأمنية (Security Alert Analyzer).**

يستقبل تنبيهات JSON، ويتحقق منها وفق مخطط موثّق، ويصنّف الخطورة بقواعد
**قابلة للتفسير**، ويُخرج تقريرًا منظمًا بصيغتي JSON وMarkdown.

القيمة الحقيقية فيما تمتنع الأداة عن فعله عن قصد:

- **لا تستخدم أي نموذج ذكاء اصطناعي.** التصنيف قواعد شفافة بأوزان ثابتة، وكل
  قرار يعيد **قائمة الأسباب المرتبة** التي أنتجته. لا صندوق أسود.
- **لا تستعلم من SIEM ولا تفتح أي اتصال شبكي.** تقرأ ملفًا محليًا وتكتب تقريرًا
  محليًا.
- **لا تنفّذ أي إجراء تلقائي.** لا تعزل جهازًا ولا تعطّل حسابًا — الإنسان يقرأ
  التقرير ويقرر.
- تحمل **تحذيرها الخاص بالإيجابيات والسلبيات الكاذبة داخل كل تقرير**، فلا يمكن
  قراءة الحكم دون رؤية التحذير.

**طريقة البناء:** الاختبار أولًا (TDD). كنت أكتب اختبارًا فاشلًا، أشاهده يفشل،
ثم أنفّذ. كشف ذلك خطأين حقيقيين أصلحتهما بدل إخفائهما — اختبار تعامل خطأً مع
عنوان RFC 5737 التوثيقي كأنه اتصال خارجي، وأداة سطر أوامر ترفض صيغة التغذية
الشائعة `{"alerts": [...]}`.

**ما تحققت منه فعليًا:**

- **30 اختبارًا تنجح** — المسار الصحيح، المدخلات غير الصالحة، والحالات الحدية.
- أداة سطر الأوامر تصنّف تغذية اصطناعية من خمسة تنبيهات عبر كامل التدرج من
  `informational` إلى `critical`، وترفض تنبيهًا غير صالح برمز خروج غير صفري.
- **مجموعة اختبارات المشروع الأصلي لم تتأثر بعملي:** 27 فشلًا مسبقًا قبل و27
  بعده، مُثبت ذلك على استنساخ نظيف. عملي يضيف 30 اختبارًا ناجحًا ولا يكسر شيئًا.

**ما لا أدّعيه:** لا أرقام أداء، ولا مقاييس دقة، ولا "قصص نجاح". لم أقِس أي شيء،
فلا أذكر شيئًا. الأداة مدخل للفرز، وليست استنتاجًا نهائيًا.

الكود والاختبارات والتوثيق كاملة في المستودع، مع الحفاظ على الإسناد للمؤلف
الأصلي وعدم تغيير رخصة MIT.

شكرًا لـ M507 على إتاحة المنصة علنًا — قراءة كود SOC حقيقي علّمتني أكثر من أي
درس تعليمي.

#الأمن_السيبراني #SOC #هندسة_الكشف #الفريق_الأزرق #بايثون #مفتوح_المصدر
