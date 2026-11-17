---
title: طرح گزارش
description: سند JSON نسخه‌دار که nw test --output json چاپ می‌کند.
weight: 5
source_rev: d05013e4fb0591e6e6d376a1f346b40f5e8102ea
---

`nw test ... --output json` یک سند JSON در خروجی استاندارد چاپ می‌کند. برای اسکریپت‌ها و ابزارهای دیگر ساخته شده و به شکل خروجی ترمینال وابسته نیست.

تعریف ماشین‌خوان یک JSON Schema است: [report.v1.json](/schema/report.v1.json). هر سند شامل `"schema_version": "1"` است.

## تعهد سازگاری

در نسخه 1 طرح، فیلدها هرگز تغییر نام نمی‌دهند، حذف نمی‌شوند و معنی‌شان عوض نمی‌شود. فیلد جدید ممکن است اضافه شود، پس خواننده‌ها باید فیلدهای ناشناس را نادیده بگیرند. تغییر ناسازگار یعنی `schema_version` جدید و در همین‌جا مستند می‌شود.

## ساختار

یک گزارش شامل `schema_version`، `run` و فهرست‌های `measurements`، `findings`، `hypotheses` و `recommendations` است. فهرست‌ها همیشه هستند و آرایه‌اند، هرگز `null` نیستند. `nw test` فهرست‌های `findings`، `hypotheses` و `recommendations` را خالی می‌گذارد؛ `nw diagnose` آن‌ها را پر می‌کند و `summary` را اضافه می‌کند. فیلدهای یافته، فرضیه و پیشنهاد در [نسخه انگلیسی این صفحه](https://github.com/hesamzakerirad/nwrk/blob/main/docs/report-schema.md) و در [یافته‌ها](../findings/) توضیح داده شده‌اند.

مثال کامل با آدرس‌ها و زمان‌های نمایشی (نه اندازه‌گیری واقعی) در [نسخه انگلیسی این صفحه](https://github.com/hesamzakerirad/nwrk/blob/main/docs/report-schema.md) آمده است.

## فیلدهای اندازه‌گیری

| فیلد | معنی |
|---|---|
| `id` | `m-001`، `m-002` و ... به ترتیب گزارش، پایدار در یک گزارش |
| `type` | `dns`، `tcp`، `tls`، `http` یا `local` (بررسی خود این دستگاه، از `nw doctor`) |
| `scope` | `local`، `domestic` یا `international`، تعیین‌شده توسط `nw doctor` |
| `version` | نسخه پیاده‌سازی اندازه‌گیری |
| `status` | `success`، `failure`، `skipped` یا `inconclusive` |
| `started_at`، `ended_at`، `duration_ms` | زمان اجرا و مدت آن |
| `target` | هر کدام از `host`، `url`، `ip`، `port`، `family` (`ipv4` یا `ipv6`) |
| `resolver` | برای DNS: `kind` (`system`، `udp` یا `tcp`)، `address` و برای resolver سیستم `servers` |
| `params` | پارامترهای آزمایش، مثل `method` یا `max_redirects` |
| `result` | در موفقیت، و در شکست‌هایی که شاهد جزئی به جا گذاشته‌اند وجود دارد. فیلدهایش به `type` بستگی دارد؛ به طرح نگاه کنید |
| `error` | در شکست وجود دارد: `code` (پایدار، [اندازه‌گیری‌ها](../measurements/) را ببینید) و `message` (برای انسان، ممکن است تغییر کند) |
| `note` | در `skipped` وجود دارد: چرا اجرا نشد |
| `redacted` | آنچه عمداً جمع‌آوری نشده، مثلاً `response.set-cookie` |

در اسکریپت‌ها از `error.code` استفاده کنید، نه `error.message`.

برای `nw doctor`، `summary` علاوه بر آن `scopes` (فهرست `{scope, status}`) و `verdict` (`healthy`، `local`، `domestic`، `international`، `upstream` یا `partial`) دارد و `run.region` پیش‌تنظیم منطقه است؛ [منطقه‌ها و پیش‌تنظیم‌ها](../regions/) را ببینید. دستورهای `nw network`، `nw config path` و `nw config show` با `--output json` سندهای JSON کوچک خودشان را چاپ می‌کنند، هر کدام با `schema_version` و همان تعهد سازگاری.

## وضعیت خروج

سند JSON جای وضعیت خروج را نمی‌گیرد. برای `nw test`: `0` همه اندازه‌گیری‌ها موفق، `1` دست‌کم یکی ناموفق. برای `nw diagnose`: `0` یافته قابل اقدامی نیست، `1` دست‌کم یکی هست. در هر دو: `2` خطای استفاده، `130` متوقف‌شده. خطاهایی که پیش از هر اندازه‌گیری nw را متوقف می‌کنند، مثل گزینه نادرست، به جای آن `{"schema_version": "1", "error": {"kind", "message"}}` را در خروجی خطا چاپ می‌کنند.
