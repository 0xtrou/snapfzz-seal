import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'Snapfzz Seal',
  tagline: 'Encrypted, sandbox-bound agent delivery system',
  favicon: 'img/favicon.svg',

  future: {
    v4: true,
  },

  url: 'https://snapfzz-seal.snapfzz.com',
  baseUrl: '/',

  organizationName: '0xtrou',
  projectName: 'snapfzz-seal',

  onBrokenLinks: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/0xtrou/snapfzz-seal/tree/main/website/',
          sidebarCollapsed: false,
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: 'img/social-card.jpg',
    colorMode: {
      respectPrefersColorScheme: true,
    },
    docs: {
      sidebar: {
        hideable: false,
        autoCollapseCategories: false,
      },
    },
    navbar: {
      title: 'Snapfzz Seal',
      logo: {
        alt: 'Snapfzz Seal Logo',
        src: 'img/logo.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Documentation',
        },
        {
          href: 'https://github.com/0xtrou/snapfzz-seal',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {
              label: 'Getting Started',
              to: '/docs/getting-started/installation',
            },
            {
              label: 'How It Works',
              to: '/docs/getting-started/how-it-works',
            },
            {
              label: 'CLI Reference',
              to: '/docs/reference/cli',
            },
          ],
        },
        {
          title: 'Security',
          items: [
            {
              label: 'Threat Model',
              to: '/docs/security/threat-model',
            },
            {
              label: 'Security Audits',
              to: '/docs/security/audits',
            },
          ],
        },
        {
          title: 'Community',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/0xtrou/snapfzz-seal',
            },
            {
              label: 'Issues',
              href: 'https://github.com/0xtrou/snapfzz-seal/issues',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Snapfzz Seal Contributors`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['rust', 'toml', 'bash'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;