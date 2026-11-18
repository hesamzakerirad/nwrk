---
title: نصب
description: نصب nw روی لینوکس، مک یا ویندوز و بررسی صحت فایل دانلودشده.
weight: 2
source_rev: 6d76586250260874cb6dfd421f19bc95a4064969
---

nw یک فایل اجرایی واحد است. نیازی به Go، حساب کاربری یا دسترسی مدیر سیستم ندارید.

## لینوکس و مک

```sh
curl -fsSL https://nwrk.ir/install.sh | sh
```

این اسکریپت آرشیو نسخه مناسب سیستم شما را از GitHub Releases دانلود می‌کند، چک‌سام SHA-256 آن را بررسی می‌کند و `nw` را در `~/.local/bin` نصب می‌کند. اگر چک‌سام مطابقت نداشته باشد، هیچ چیزی نصب نمی‌شود.

گزینه‌ها (متغیرهای محیطی):

| متغیر | معنی | پیش‌فرض |
|---|---|---|
| `NW_VERSION` | نسخه مورد نظر، مثلاً `0.1.0` | آخرین نسخه |
| `NW_INSTALL_DIR` | پوشه نصب | `~/.local/bin` |

## ویندوز

در پاورشل:

```powershell
irm https://nwrk.ir/install.ps1 | iex
```

این اسکریپت چک‌سام را بررسی می‌کند، `nw.exe` را در `%LOCALAPPDATA%\nwrk\bin` نصب می‌کند و آن پوشه را به `PATH` کاربر اضافه می‌کند. پس از نصب یک ترمینال جدید باز کنید. متغیرهای `NW_VERSION` و `NW_INSTALL_DIR` اینجا هم کار می‌کنند.

## با Go

```sh
go install github.com/hesamzakerirad/nwrk/cmd/nw@latest
```

این روش از روی کد منبع می‌سازد و `nw` را در پوشه bin مربوط به Go قرار می‌دهد. این پوشه `$(go env GOBIN)` است، یا اگر `GOBIN` تنظیم نشده باشد `$(go env GOPATH)/bin`. برای بیشتر کاربران همان `~/go/bin` است.

وقتی نصب موفق باشد، Go فقط `go: downloading ...` چاپ می‌کند. اگر بعد از آن شل پیام `command not found: nw` داد، پوشه bin مربوط به Go در `PATH` نیست. بخش [رفع مشکل](#رفع-مشکل) را ببینید.

## دانلود دستی

آرشیو مناسب سیستم خود و فایل `checksums.txt` را از [صفحه انتشارها](https://github.com/hesamzakerirad/nwrk/releases) دانلود کنید. نام آرشیوها به شکل `nw_<version>_<os>_<arch>.tar.gz` است (در ویندوز `.zip`) و برای لینوکس، مک و ویندوز روی `amd64` و `arm64` وجود دارند. آرشیو را باز کنید و `nw` را در یکی از پوشه‌های `PATH` بگذارید.

## بررسی اینکه کار می‌کند

```sh
nw version
```

## بررسی صحت دانلود

هر نسخه شامل فایل `checksums.txt` است. آرشیو خود را با آن مقایسه کنید:

```sh
sha256sum --check --ignore-missing checksums.txt
```

در مک از `shasum -a 256 --check --ignore-missing checksums.txt` استفاده کنید.

فایل `checksums.txt` همچنین با [cosign](https://docs.sigstore.dev/) و امضای بدون کلید در GitHub Actions امضا شده است. برای اطمینان از اینکه این فایل را فرایند انتشار همین پروژه ساخته است:

```sh
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/hesamzakerirad/nwrk/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## رفع مشکل

**دانلود کند است یا شکست می‌خورد.** دسترسی به GitHub در بعضی شبکه‌ها کند یا ناپایدار است. اسکریپت‌های نصب سه بار تلاش می‌کنند. اگر باز هم شکست خورد، آدرس صفحه انتشار را نشان می‌دهند تا فایل‌ها را با هر روشی که در دسترس دارید دانلود کنید و مراحل «دانلود دستی» را انجام دهید.

**پیام `nw: command not found`.** پوشه نصب در `PATH` نیست. نصب‌کننده می‌گوید کدام پوشه را اضافه کنید. اگر با Go نصب کرده‌اید، پوشه bin مربوط به Go را اضافه کنید. برای zsh این دستور را یک بار اجرا کنید و ترمینال جدیدی باز کنید:

```sh
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc
```

برای bash به جای `~/.zshrc` از `~/.bashrc` استفاده کنید. اگر `GOBIN` را تنظیم کرده‌اید، همان پوشه را اضافه کنید. برای اجرای `nw` بدون تغییر `PATH` مسیر کامل آن را بنویسید، مثلاً `~/go/bin/nw version`.

**برنامه دیگری با نام `nw` اجرا می‌شود.** پروژه NW.js هم برنامه‌ای به نام `nw` نصب می‌کند. اگر `which nw` (در ویندوز `where nw`) به جای دیگری اشاره می‌کند، پوشه نصب nwrk را در `PATH` جلوتر قرار دهید.

## حذف

فایل اجرایی را پاک کنید: `~/.local/bin/nw` در لینوکس و مک، یا `%LOCALAPPDATA%\nwrk\bin\nw.exe` در ویندوز. فعلاً nw فایل دیگری ذخیره نمی‌کند.
