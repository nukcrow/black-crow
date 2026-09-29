<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>NukCrow</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            padding: 50px 20px;
            background: #0d1117;
            color: #c9d1d9;
            font-family: Arial, Helvetica, sans-serif;
            text-align: center;
        }

        .container {
            max-width: 900px;
            margin: auto;
        }

        .hero {
            width: 100%;
            border-radius: 12px;
        }

        .title {
            margin-top: 25px;
            font-size: 24px;
            font-weight: 600;
        }

        .subtitle {
            margin-top: 10px;
            color: #8a8f98;
            font-size: 14px;
        }

        /* Main Telegram Card */

        .telegram-card {
            width: 470px;
            max-width: 92%;
            margin: 38px auto 0;

            padding: 38px 32px;

            background: rgba(22, 27, 34, 0.72);

            border: 1px solid rgba(139, 148, 158, 0.16);

            border-radius: 22px;

            box-shadow:
                0 18px 50px rgba(0, 0, 0, 0.28),
                inset 0 1px 0 rgba(255, 255, 255, 0.025);

            backdrop-filter: blur(10px);
        }

        .telegram-icon {
            width: 58px;
            height: 58px;

            margin-bottom: 10px;

            opacity: 0.9;
        }

        .telegram-title {
            font-size: 25px;
            font-weight: 600;
            letter-spacing: 0.2px;
        }

        .official {
            margin-top: 8px;
            color: #8a8f98;
            font-size: 13px;
        }

        /* Links */

        .links {
            margin-top: 30px;
        }

        .link {
            display: block;

            padding: 16px 18px;
            margin: 10px 0;

            text-decoration: none;
            color: #c9d1d9;

            background: rgba(13, 17, 23, 0.55);

            border: 1px solid rgba(139, 148, 158, 0.10);

            border-radius: 13px;

            transition:
                background 0.25s ease,
                border-color 0.25s ease,
                transform 0.25s ease;
        }

        .link:hover {
            background: rgba(33, 38, 45, 0.85);

            border-color: rgba(139, 148, 158, 0.28);

            transform: translateY(-2px);
        }

        .link-name {
            font-size: 14px;
            font-weight: 600;
            letter-spacing: 0.4px;
        }

        .username {
            margin-top: 5px;

            color: #8a8f98;

            font-size: 13px;
        }

        .footer {
            margin-top: 25px;

            color: #6e7681;

            font-size: 11px;
        }

    </style>
</head>

<body>

<div class="container">

    <!-- Header -->

    <img
        class="hero"
        src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:161b22,100:21262d&height=220&section=header&text=nukcrow&fontSize=65&fontColor=8A8F98&animation=fadeIn&fontAlignY=38"
        alt="NukCrow"
    >

    <div class="title">
        V2Ray / Xray Configuration Platform
    </div>

    <div class="subtitle">
        Automated • Tested • Quality Ranked
    </div>


    <!-- Telegram Card -->

    <div class="telegram-card">

        <a href="https://t.me/nukcrow" target="_blank">
            <img
                class="telegram-icon"
                src="https://cdn.simpleicons.org/telegram/8A8F98"
                alt="Telegram"
            >
        </a>

        <div class="telegram-title">
            Telegram
        </div>

        <div class="official">
            Official NukCrow Services
        </div>


        <div class="links">

            <a
                class="link"
                href="https://t.me/nukcrow"
                target="_blank"
            >
                <div class="link-name">
                    📢 CHANNEL
                </div>

                <div class="username">
                    @nukcrow
                </div>
            </a>


            <a
                class="link"
                href="https://t.me/Nukcrowbot"
                target="_blank"
            >
                <div class="link-name">
                    💬 ADMIN SUPPORT
                </div>

                <div class="username">
                    @Nukcrowbot
                </div>
            </a>


            <a
                class="link"
                href="https://t.me/nukcrowvpnbot"
                target="_blank"
            >
                <div class="link-name">
                    ⚡ CONFIGURATION BOT
                </div>

                <div class="username">
                    @nukcrowvpnbot
                </div>
            </a>

        </div>


        <div class="footer">
            NukCrow • Official Telegram Services
        </div>

    </div>

</div>

</body>
</html>
