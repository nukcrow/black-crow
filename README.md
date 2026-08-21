<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:161b22,100:21262d&height=200&section=header&text=BLACK%20CROW&fontSize=60&fontColor=8A8F98&animation=fadeIn&fontAlignY=38" width="100%"/>

<img src="https://readme-typing-svg.demolab.com/?font=Fira+Code&weight=500&size=20&duration=3000&pause=1000&color=A9A9C8&background=00000000&center=true&vCenter=true&width=560&lines=V2Ray+%2F+Xray+Config+Aggregator;Auto-tested+%26+Quality-Ranked;Powered+by+GitHub+Actions" alt="typing-svg"/>

<br/><br/>

![License](https://img.shields.io/badge/License-MIT-0d1117?style=for-the-badge)
![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-0d1117?style=for-the-badge&logo=githubactions&logoColor=white)
![Python](https://img.shields.io/badge/Python-0d1117?style=for-the-badge&logo=python&logoColor=white)
![Cloudflare Workers](https://img.shields.io/badge/Cloudflare%20Workers-0d1117?style=for-the-badge&logo=cloudflareworkers&logoColor=white)
![Telegram Bot](https://img.shields.io/badge/Telegram%20Bot-0d1117?style=for-the-badge&logo=telegram&logoColor=white)

</div>

<br/>

## درباره

**Black Crow** یه سیستم خودکار جمع‌آوری و رتبه‌بندی کانفیگ‌های V2Ray/Xray هست که کاملاً روی GitHub Actions اجرا می‌شه — بدون نیاز به سرور دائمی.

## ویژگی‌ها

- 🔄 **جمع‌آوری موازی** از چند منبع/ریپوی مرجع هم‌زمان
- 🧹 **حذف تکراری‌ها** بر اساس شناسه‌ی واقعی سرور
- 📡 **تست اتصال TCP** روی همه‌ی کانفیگ‌ها
- 🏆 **رتبه‌بندی کیفیت** (اولویت با TLS+WS/gRPC/xHTTP و پروتکل Reality)
- 📦 **خروجی‌های چندگانه**: فایل‌های تفکیک‌شده بر اساس پروتکل، ساب‌لینک عمومی، و یه ساب پرمیوم بهینه‌شده برای موبایل با کمترین تاخیر (`persian crow | Xms`)
- ⚡ **Cloudflare Worker** برای سرو کردن مجموعه‌ی چرخشی از کانفیگ‌ها در هر درخواست
- 🤖 **بات تلگرام فروش اشتراک** با پرداخت کارت‌به‌کارت، ثبت سفارش در SQLite، و تحویل خودکار از طریق پنل 3x-ui

## نحوه‌ی کار

هر اجرا (Workflow) به‌صورت خودکار: منابع رو fetch می‌کنه → دیدوپلیکیت می‌کنه → تست TCP انجام می‌ده → دسته‌بندی و رتبه‌بندی می‌کنه → ساب‌لینک‌های خروجی رو آپدیت می‌کنه.

<br/>

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:161b22,100:21262d&height=120&section=footer" width="100%"/>

</div>
