export const MODERN_THEME_STYLE = String.raw`:root {
            color-scheme: dark;
            --page: #0b1016;
            --sidebar: #111a24;
            --panel: #151f2a;
            --panel-raised: #192531;
            --field: #101821;
            --code: #0b1219;
            --ink: #f2f6fb;
            --muted: #8ea1b5;
            --muted-strong: #b7c5d4;
            --line: #2a3b4c;
            --line-soft: rgba(151, 178, 204, 0.15);
            --cyan: #54d9ff;
            --cyan-strong: #0da9dc;
            --cyan-soft: rgba(84, 217, 255, 0.12);
            --lime: #58df91;
            --lime-soft: rgba(88, 223, 145, 0.12);
            --amber: #f2a45d;
            --amber-soft: rgba(242, 164, 93, 0.13);
            --rose: #f27686;
            --rose-soft: rgba(242, 118, 134, 0.12);
            --shadow: 0 22px 60px rgba(0, 0, 0, 0.22);
        }

        :root[data-theme="light"] {
            color-scheme: light;
            --page: #f4f7fa;
            --sidebar: #ffffff;
            --panel: #ffffff;
            --panel-raised: #f6f8fb;
            --field: #ffffff;
            --code: #eef3f7;
            --ink: #17212b;
            --muted: #6c7d8f;
            --muted-strong: #46586a;
            --line: #d7e1ea;
            --line-soft: rgba(75, 100, 124, 0.14);
            --cyan: #079dce;
            --cyan-strong: #047da8;
            --cyan-soft: rgba(7, 157, 206, 0.11);
            --lime: #2eaf68;
            --lime-soft: rgba(46, 175, 104, 0.11);
            --amber: #bf701c;
            --amber-soft: rgba(191, 112, 28, 0.11);
            --rose: #d64f63;
            --rose-soft: rgba(214, 79, 99, 0.1);
            --shadow: 0 16px 38px rgba(34, 53, 72, 0.08);
        }

        html {
            background: var(--page);
        }

        body {
            background: var(--page);
            color: var(--ink);
            font-size: 14px;
            line-height: 1.45;
        }

        .shell {
            grid-template-columns: 252px minmax(0, 1fr);
        }

        .sidebar {
            position: sticky;
            top: 0;
            height: 100vh;
            align-content: start;
            overflow-y: auto;
            background: var(--sidebar);
            border-right: 1px solid var(--line);
            padding: 24px 18px 20px;
            gap: 22px;
        }

        .brand {
            gap: 11px;
        }

        .mark,
        .project-icon {
            border-radius: 13px;
            background: var(--cyan);
            color: #06131b;
            box-shadow: none;
        }

        .brand h1 {
            font-size: 16px;
            letter-spacing: -0.02em;
        }

        .brand span,
        .sidebar .tiny {
            color: var(--muted);
        }

        .account,
        .project-link,
        .flow-step,
        .stat {
            border-color: var(--line-soft);
            background: var(--panel-raised);
        }

        .account {
            border-radius: 14px;
            padding: 14px;
        }

        .account .button.secondary {
            width: 100%;
            min-height: 36px;
            background: transparent;
            color: var(--muted-strong);
            border-color: var(--line);
        }

        .project-list {
            gap: 6px;
            margin-top: 8px;
        }

        .project-link {
            border-radius: 12px;
            padding: 9px;
        }

        .project-link:hover,
        .project-link.active {
            background: var(--cyan-soft);
            border-color: rgba(84, 217, 255, 0.34);
        }

        .project-link .project-icon {
            width: 34px;
            height: 34px;
        }

        .main {
            width: 100%;
            max-width: 1540px;
            padding: 34px clamp(24px, 4vw, 52px) 48px;
            gap: 24px;
        }

        .topbar {
            align-items: center;
            padding-bottom: 2px;
        }

        h2 {
            font-size: clamp(30px, 3.3vw, 44px);
            letter-spacing: -0.045em;
        }

        h3 {
            font-size: 17px;
            letter-spacing: -0.02em;
        }

        .label {
            color: var(--muted);
            font-size: 11px;
            letter-spacing: 0.08em;
        }

        .meta,
        .label {
            color: var(--muted);
        }

        .actions {
            gap: 8px;
        }

        .button,
        .icon-button {
            min-height: 42px;
            border-radius: 11px;
            border: 1px solid transparent;
            background: var(--cyan);
            color: #07151c;
            padding: 0 15px;
            font-size: 13px;
            font-weight: 800;
            transition: transform 140ms ease, border-color 140ms ease, background 140ms ease;
        }

        .button:hover,
        .icon-button:hover {
            transform: translateY(-1px);
        }

        .button.secondary {
            background: var(--panel-raised);
            color: var(--muted-strong);
            border-color: var(--line);
        }

        .button.secondary:hover {
            color: var(--ink);
            border-color: var(--cyan);
        }

        .button.danger {
            background: var(--rose-soft);
            color: var(--rose);
            border-color: rgba(242, 118, 134, 0.35);
        }

        .icon-button.theme-toggle {
            width: 42px;
            padding: 0;
            background: var(--panel-raised);
            color: var(--muted-strong);
            border-color: var(--line);
        }

        .theme-toggle svg {
            width: 18px;
            height: 18px;
        }

        .panel,
        .card {
            border-radius: 17px;
            border-color: var(--line);
            background: var(--panel);
            box-shadow: var(--shadow);
        }

        .panel {
            padding: 22px;
            gap: 18px;
        }

        .card {
            padding: 16px;
            gap: 14px;
        }

        .summary {
            grid-template-columns: 52px minmax(0, 1fr);
        }

        .summary .project-icon {
            width: 52px;
            height: 52px;
            font-size: 16px;
        }

        .stats {
            gap: 8px;
        }

        .stat {
            min-height: 68px;
            border-radius: 12px;
            padding: 12px;
        }

        .stat strong {
            font-size: 21px;
        }

        .field {
            gap: 6px;
        }

        input,
        select,
        textarea {
            min-height: 44px;
            border-radius: 10px;
            border-color: var(--line);
            background: var(--field);
            color: var(--ink);
            padding: 10px 12px;
            outline: none;
            transition: border-color 140ms ease, box-shadow 140ms ease;
        }

        input:focus,
        select:focus,
        textarea:focus {
            border-color: var(--cyan);
            box-shadow: 0 0 0 3px var(--cyan-soft);
        }

        .dropzone {
            min-height: 164px;
            border: 1px dashed var(--cyan);
            border-radius: 14px;
            background: var(--cyan-soft);
            color: var(--ink);
            transition: background 140ms ease, border-color 140ms ease;
        }

        .dropzone:hover {
            background: rgba(84, 217, 255, 0.18);
            border-color: var(--cyan-strong);
        }

        .dropzone strong {
            font-size: 15px;
        }

        .flow {
            position: relative;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 8px;
            padding-top: 8px;
        }

        .flow::before {
            content: "";
            position: absolute;
            top: 27px;
            left: 9%;
            right: 9%;
            border-top: 1px solid var(--line);
        }

        .flow-step {
            position: relative;
            z-index: 1;
            min-height: 72px;
            border-radius: 12px;
            text-align: center;
            padding: 13px 8px 10px;
        }

        .flow-step::before {
            content: "";
            display: block;
            width: 12px;
            height: 12px;
            margin: -20px auto 9px;
            border: 2px solid var(--cyan);
            border-radius: 50%;
            background: var(--panel);
        }

        .build-head {
            align-items: center;
        }

        .badges {
            gap: 6px;
        }

        .badge {
            min-height: 26px;
            border: 1px solid var(--line);
            border-radius: 999px;
            background: var(--cyan-soft);
            color: var(--cyan);
            padding: 0 9px;
            font-size: 11px;
        }

        .badge.qa,
        .badge.tag {
            background: var(--amber-soft);
            color: var(--amber);
        }

        .badge.live {
            background: var(--lime-soft);
            color: var(--lime);
        }

        .code {
            border-color: var(--line);
            border-radius: 10px;
            background: var(--code);
            color: var(--muted-strong);
            padding: 11px 12px;
        }

        .split-actions {
            border-top: 1px solid var(--line-soft);
            padding-top: 14px;
        }

        .inline-form select {
            min-width: 128px;
        }

        .alert {
            border-color: rgba(242, 164, 93, 0.4);
            border-radius: 12px;
            background: var(--amber-soft);
            color: var(--amber);
        }

        .soft-load {
            border-radius: 14px;
            border-color: var(--line);
            background: var(--panel);
            color: var(--ink);
            box-shadow: var(--shadow);
        }

        .soft-load span {
            color: var(--muted);
        }

        .spinner {
            border-color: var(--line);
            border-top-color: var(--cyan);
        }

        @media (max-width: 980px) {
            .sidebar {
                position: static;
                height: auto;
                border-right: 0;
                border-bottom: 1px solid var(--line);
            }

            .shell {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 640px) {
            .main,
            .sidebar {
                padding: 20px 16px;
            }

            .flow,
            .stats,
            .build-meta,
            .form-grid[style] {
                grid-template-columns: 1fr !important;
            }

            .flow::before {
                display: none;
            }

            .flow-step::before {
                margin-top: -4px;
            }

            .topbar {
                gap: 16px;
            }
        }`;

