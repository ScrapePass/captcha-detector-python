/*! captcha-detector v1.0.0 | MIT License | https://github.com/ScrapePass/captcha-detector */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else if (typeof define === 'function' && define.amd) define([], factory);
  else root.CaptchaDetector = factory();
})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this, function () {
'use strict';
/**
 * Captcha / bot-check signatures.
 *
 * Each signature describes one captcha or bot-protection product. A page matches a signature when one or more of its
 * matchers hit; each hit adds evidence with a weight, and the weights are combined into a confidence (noisy-or).
 *
 * Fields
 *   id, name, vendor, site    who it is
 *   kind                      'widget'          a captcha widget on the page (checkbox, puzzle, slider, image grid…)
 *                             'invisible'       runs in the background, shows a challenge only when it is suspicious
 *                             'image'           a classic image of distorted characters to type
 *                             'question'        a text or math question to answer
 *                             'challenge-page'  the whole page is a bot check that stands in front of the content
 *                             'block-page'      access denied, nothing to solve
 *                             'protection'      a bot-protection service is loaded; it can raise a captcha later
 *   subtype                   free text: 'checkbox', 'slider', 'press-and-hold', 'proof-of-work', …
 *   generic                   true for the catch-all rules; they are dropped when a named product is found
 *
 * Matchers (all optional; a weight can be given as [pattern, weight])
 *   scripts   RegExp tested on script URLs (and, in the browser, on every resource the page loaded)
 *   frames    RegExp tested on iframe URLs
 *   elements  CSS selector (simple compound selectors only: tag, #id, .class, [attr op "value" i], :not(...)),
 *             or { sel, attr: [...names], re } to test attributes of the selected elements with a RegExp
 *   inline    RegExp tested on the text of inline scripts
 *   globals   window property path ('grecaptcha.enterprise') or a function (window) => boolean; browser only
 *   urls      RegExp tested on the page URL
 *   title     RegExp tested on the page title
 *   text      RegExp tested on the visible text, only on short pages (a bot-check page is short), unless the
 *             entry is [re, weight, 'any']
 *   cookies   cookie name: exact string, a prefix ending in '_' or '-', or a RegExp
 *   headers   [header-name, RegExp, weight?] tested on response headers (when you pass them)
 *   status    response status codes (supporting evidence only)
 *   refine    (detection, ctx) => detection | null, to work out the variant, the visibility, or to drop a weak match
 */

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const CAPTCHA_IMG = /captch|kaptcha|check_?code|verif(?:y|ication)_?(?:code|img|image|pic)|valid(?:ate)?_?code|(?:^|[^a-z])v_?code|secur(?:e|ity)_?code_?img|auth_?code|image_?code|img_?code|pic_?code|rand_?code|(?:^|[^a-z])yzm(?:[^a-z]|$)|securimage/i;
const NOT_CAPTCHA_IMG = /logo|icon|badge|sprite|avatar|banner|screenshot|thumb|favicon/i;
/** Images that look like a captcha to solve (not a logo, an icon or an illustration of one). */
const captchaImages = (x) =>
  x
    .query('img')
    .concat(x.query('canvas'))
    .filter((n) => {
      const a = [n.attr('src'), n.attr('id'), n.attr('class'), n.attr('alt'), n.attr('name'), n.attr('title')].join(' ');
      const src = n.attr('src') || '';
      return CAPTCHA_IMG.test(a) && !NOT_CAPTCHA_IMG.test(a) && !/\.svg(?:[?#]|$)/i.test(src);
    });

const SIGNATURES = [
  // ───────────────────────────── Major captcha widgets ─────────────────────────────
  {
    id: 'recaptcha',
    name: 'reCAPTCHA',
    vendor: 'Google',
    kind: 'widget',
    site: 'https://developers.google.com/recaptcha',
    scripts: [
      /\b(?:google\.com|recaptcha\.net)\/recaptcha\/(?:api|enterprise)\.js/i,
      /\bgstatic\.(?:com|cn)\/recaptcha\//i,
      [/\b(?:google\.com|recaptcha\.net)\/recaptcha\/(?:api2|enterprise)\/(?:reload|userverify|clr|webworker)/i, 0.8],
    ],
    frames: [/\b(?:google\.com|recaptcha\.net)\/recaptcha\/(?:api2|enterprise)\/(?:anchor|bframe)/i],
    elements: [
      '.g-recaptcha',
      '#g-recaptcha',
      '.grecaptcha-badge',
      ['textarea[name="g-recaptcha-response"]', 0.7],
      ['iframe[title="reCAPTCHA"]', 0.9],
    ],
    inline: [[/\bgrecaptcha\.(?:execute|render|ready|enterprise)\b/, 0.75]],
    globals: ['grecaptcha', '___grecaptcha_cfg'],
    refine(d, x) {
      // hCaptcha's reCAPTCHA compatibility mode adds a g-recaptcha-response textarea and window.grecaptcha.
      if (x.has('hcaptcha') && !d.evidence.some((e) => e.type === 'scripts' || e.type === 'frames' || e.type === 'inline' || /\.g-recaptcha|grecaptcha-badge/.test(e.value))) return null;
      const anchors = x.frames(/\/recaptcha\/(?:api2|enterprise)\/anchor/i);
      const bframes = x.frames(/\/recaptcha\/(?:api2|enterprise)\/bframe/i);
      const checkbox = anchors.filter((f) => !/[?&]size=invisible/i.test(f.src));
      const invisibleAnchor = anchors.some((f) => /[?&]size=invisible/i.test(f.src));
      const widgets = x.query('.g-recaptcha');
      const invisibleWidget = widgets.some((n) => /invisible/i.test(n.attr('data-size') || ''));
      const v3 = x.script(/\/recaptcha\/(?:api|enterprise)\.js\?(?:[^#]*&)?render=(?!explicit\b|onload\b)[\w-]{20,}/i);
      const enterprise = x.script(/\/recaptcha\/enterprise/i) || anchors.some((f) => /\/enterprise\//.test(f.src)) || x.global('grecaptcha.enterprise');
      d.name = enterprise ? 'reCAPTCHA Enterprise' : 'reCAPTCHA';
      if (checkbox.length) {
        d.subtype = 'v2-checkbox';
        d.visible = x.anyVisible(checkbox);
      } else if (invisibleWidget || (invisibleAnchor && !v3)) {
        d.subtype = 'v2-invisible';
        d.kind = 'invisible';
        d.visible = x.dom ? false : null;
      } else if (v3 || invisibleAnchor) {
        d.subtype = 'v3';
        d.kind = 'invisible';
        d.visible = x.dom ? false : null;
      } else if (widgets.length) {
        d.subtype = 'v2-checkbox';
        d.visible = x.anyVisible(widgets);
      } else {
        d.subtype = 'v2';
        d.visible = x.dom ? false : null;
      }
      if (bframes.length && x.anyVisible(bframes)) {
        d.visible = true;
        d.details = { ...d.details, challengeOpen: true };
      }
      return d;
    },
  },
  {
    id: 'hcaptcha',
    name: 'hCaptcha',
    vendor: 'Intuition Machines',
    kind: 'widget',
    site: 'https://www.hcaptcha.com',
    scripts: [/\b(?:js|api|api2|newassets|assets|imgs\d*)\.hcaptcha\.com\//i, /\/\/hcaptcha\.com\/1\/(?:secure-)?api\.js/i],
    frames: [/\bhcaptcha\.com\/captcha\/v1\//i, /\b(?:new)?assets\.hcaptcha\.com\//i],
    elements: ['.h-captcha', 'textarea[name="h-captcha-response"]', '[data-hcaptcha-widget-id]', ['iframe[title*="hCaptcha" i]', 0.9]],
    inline: [[/\bhcaptcha\.(?:execute|render)\s*\(/, 0.75]],
    globals: ['hcaptcha'],
    refine(d, x) {
      const checkbox = x.frames(/[#&]frame=checkbox(?:&|$)|hcaptcha-checkbox\.html/i);
      const invisibleFrame = x.frames(/[#&]frame=checkbox-invisible/i);
      const challenge = x.frames(/[#&]frame=challenge|hcaptcha-challenge\.html/i);
      const widgets = x.query('.h-captcha');
      const invisible = invisibleFrame.length > 0 || widgets.some((n) => /invisible/i.test(n.attr('data-size') || ''));
      if (invisible && !checkbox.length) {
        d.kind = 'invisible';
        d.subtype = 'invisible';
        d.visible = x.dom ? false : null;
      } else {
        d.subtype = 'checkbox';
        if (checkbox.length) d.visible = x.anyVisible(checkbox);
        else if (widgets.length) d.visible = x.anyVisible(widgets);
      }
      if (challenge.length && x.anyVisible(challenge)) {
        d.visible = true;
        d.details = { ...d.details, challengeOpen: true };
      }
      return d;
    },
  },
  {
    id: 'turnstile',
    name: 'Turnstile',
    vendor: 'Cloudflare',
    kind: 'widget',
    site: 'https://www.cloudflare.com/products/turnstile/',
    scripts: [/\bchallenges\.cloudflare\.com\/turnstile\//i],
    frames: [/\bchallenges\.cloudflare\.com\/cdn-cgi\/challenge-platform\/[^?#]*turnstile/i],
    elements: ['.cf-turnstile', 'input[name="cf-turnstile-response"]', ['[id^="cf-chl-widget-"]', 0.9]],
    inline: [[/\bturnstile\.(?:render|execute)\s*\(/, 0.75]],
    globals: ['turnstile'],
    refine(d, x) {
      const boxes = x.query('.cf-turnstile');
      const inputs = x.query('input[name="cf-turnstile-response"]');
      const frames = x.frames(/challenges\.cloudflare\.com/i).filter((f) => f.el);
      if (frames.length) d.visible = x.anyVisible(frames);
      else if (boxes.length) d.visible = x.anyVisible(boxes);
      else if (inputs.length && x.dom) d.visible = inputs.some((n) => x.visibleEl(n.el && n.el.parentElement));
      if (boxes.some((n) => /interaction-only|execute/i.test(n.attr('data-appearance') || '') || /invisible/i.test(n.attr('data-size') || ''))) {
        d.subtype = 'interaction-only';
      } else d.subtype = 'managed';
      return d;
    },
  },
  {
    id: 'arkose',
    name: 'Arkose Labs (FunCaptcha)',
    vendor: 'Arkose Labs',
    kind: 'widget',
    site: 'https://www.arkoselabs.com',
    scripts: [/\barkoselabs\.[a-z0-9.-]+\//i, /\bfuncaptcha\.com\//i, [/\/fc\/(?:api|gc|gt2|gfct|ca)\//i, 0.7], [new RegExp(`/v2/${UUID}/api\\.js`, 'i'), 0.6]],
    frames: [/\barkoselabs\.[a-z0-9.-]+\//i, /\bfuncaptcha\.com\//i, [/\/fc\/(?:gc|assets)\//i, 0.75]],
    elements: [
      '#FunCaptcha',
      '#funcaptcha',
      '#arkose',
      '#arkoseFrame',
      '#arkose-iframe',
      '#enforcementFrame',
      'iframe[data-e2e="enforcement-frame"]',
      'input[name="fc-token"]',
      '#fc-token',
      ['iframe[title*="arkose" i]', 0.9],
      ['[data-pkey]', 0.6],
    ],
    inline: [[/\bArkoseEnforcement\b|\bsetupEnforcement\b|\barkoseLabsClientApi/, 0.75]],
    globals: ['ArkoseEnforcement', [(w) => Object.keys(w).some((k) => /^arkoseLabsClientApi/i.test(k)), 0.85]],
    subtype: 'puzzle',
  },
  {
    id: 'geetest',
    name: 'GeeTest',
    vendor: 'GeeTest',
    kind: 'widget',
    site: 'https://www.geetest.com',
    scripts: [/\b(?:static|api|apiv6|gcaptcha4|monitor)\.geetest\.com\//i, /\bgeetest\.com\/(?:static|v4)\//i, /\bgeevisit\.com\//i, [/\bgt4?(?:\.min)?\.js\b/i, 0.4]],
    frames: [/\bgeetest\.com\//i],
    elements: [
      '.geetest_holder',
      '.geetest_panel',
      '.geetest_widget',
      '.geetest_radar',
      '.geetest_btn',
      '.geetest_box',
      '.geetest_captcha',
      '.geetest_popup_wrap',
      'input[name="geetest_challenge"]',
      'input[name="geetest_validate"]',
      'input[name="geetest_seccode"]',
      ['[class*="geetest_"]', 0.8],
    ],
    inline: [/\binitGeetest4?\s*\(/],
    globals: ['initGeetest', 'initGeetest4'],
    refine(d, x) {
      const v4 = x.script(/gcaptcha4|\/v4\/|gt4/i) || x.query('.geetest_box').length > 0 || x.global('initGeetest4') || /initGeetest4/.test(x.inline);
      d.subtype = v4 ? 'v4' : 'v3';
      return d;
    },
  },
  {
    id: 'aws-waf',
    name: 'AWS WAF CAPTCHA',
    vendor: 'Amazon Web Services',
    kind: 'widget',
    site: 'https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge.html',
    scripts: [/\.(?:token|captcha|edge\.sdk|edge\.captcha-sdk)\.awswaf\.com\//i, [/\bawswaf\.com\//i, 0.85]],
    frames: [/\bawswaf\.com\//i],
    elements: ['awswaf-captcha', ['#captcha-container', 0.35], ['#amzn-captcha-verify-button', 0.8]],
    inline: [[/\bgokuProps\b/, 0.85], [/AwsWafCaptcha\.renderCaptcha/, 0.95], [/\bAwsWafIntegration\b/, 0.6]],
    globals: [['AwsWafCaptcha', 0.9], ['gokuProps', 0.85], ['AwsWafIntegration', 0.7]],
    headers: [['x-amzn-waf-action', /captcha|challenge/i, 0.95]],
    text: [/let(?:'|’)s confirm you are human/i, [/to continue,? please confirm you(?:'|’)re a human/i, 0.7]],
    refine(d, x) {
      const captcha =
        x.script(/captcha(?:-sdk)?\.awswaf\.com|\.captcha\.awswaf/i) ||
        x.query('awswaf-captcha').length > 0 ||
        x.global('AwsWafCaptcha') ||
        /AwsWafCaptcha/.test(x.inline) ||
        /captcha/i.test(x.header('x-amzn-waf-action'));
      const challenge = /\bgokuProps\b/.test(x.inline) || x.global('gokuProps') || /challenge/i.test(x.header('x-amzn-waf-action'));
      if (captcha) {
        d.kind = x.short && challenge ? 'challenge-page' : 'widget';
        d.subtype = 'image-grid';
        if (d.kind === 'challenge-page') d.visible = true;
      } else if (challenge) {
        d.name = 'AWS WAF Challenge';
        d.kind = 'challenge-page';
        d.subtype = 'silent-challenge';
        d.visible = true;
      } else {
        d.name = 'AWS WAF Bot Control';
        d.kind = 'protection';
      }
      return d;
    },
  },
  {
    id: 'friendly-captcha',
    name: 'Friendly Captcha',
    vendor: 'Friendly Captcha',
    kind: 'widget',
    subtype: 'proof-of-work',
    site: 'https://friendlycaptcha.com',
    scripts: [/\bfriendly-challenge\b/i, /@friendlycaptcha\//i, /\b(?:api|eu-api|global\.frcapi)\.friendlycaptcha\.(?:com|eu)\//i, /\bfrcapi\.com\//i],
    elements: ['.frc-captcha', 'input[name="frc-captcha-solution"]', 'input[name="frc-captcha-response"]', 'frc-captcha'],
    globals: ['friendlyChallenge', 'frcaptcha'],
  },
  {
    id: 'mtcaptcha',
    name: 'MTCaptcha',
    vendor: 'MTCaptcha',
    kind: 'widget',
    site: 'https://www.mtcaptcha.com',
    scripts: [/\bservice2?\.mtcaptcha\.com\//i],
    frames: [/\bservice2?\.mtcaptcha\.com\//i],
    elements: ['.mtcaptcha', 'input[name="mtcaptcha-verifiedtoken"]', ['[id^="mtcaptcha"]', 0.8]],
    globals: ['mtcaptchaConfig', ['mtcaptcha', 0.8]],
    inline: [[/\bmtcaptchaConfig\b/, 0.9]],
  },
  {
    id: 'yandex-smartcaptcha',
    name: 'Yandex SmartCaptcha',
    vendor: 'Yandex',
    kind: 'widget',
    site: 'https://yandex.cloud/en/services/smartcaptcha',
    scripts: [/\bsmartcaptcha\.(?:yandexcloud\.net|cloud\.yandex\.(?:ru|net|com))\//i],
    frames: [/\bsmartcaptcha\.(?:yandexcloud\.net|cloud\.yandex\.(?:ru|net|com))\//i],
    elements: ['.smart-captcha', 'input[name="smart-token"]'],
    globals: ['smartCaptcha'],
  },
  {
    id: 'tencent-captcha',
    name: 'Tencent Captcha (TCaptcha)',
    vendor: 'Tencent',
    kind: 'widget',
    subtype: 'slider',
    site: 'https://cloud.tencent.com/product/captcha',
    scripts: [/\b(?:ssl\.|t\.)?captcha\.qq\.com\//i, /\bturing\.captcha\.(?:qcloud|gtimg)\.com\//i, /\bcaptcha\.gtimg\.com\//i, [/\bTCaptcha(?:-global)?\.js/i, 0.9]],
    frames: [/\bcaptcha\.qq\.com\//i, /\bturing\.captcha\.(?:qcloud|gtimg)\.com\//i],
    elements: ['#tcaptcha_transform', '#tcaptcha_iframe', '#tcaptcha_iframe_dy', ['[id^="tcaptcha"]', 0.85], '.tcaptcha-transform'],
    globals: ['TencentCaptcha'],
  },
  {
    id: 'aliyun-captcha',
    name: 'Alibaba Cloud Captcha',
    vendor: 'Alibaba',
    kind: 'widget',
    subtype: 'slider',
    site: 'https://www.alibabacloud.com/product/captcha',
    scripts: [
      /aliyunCaptcha\/AliyunCaptcha\.js/i,
      /\bcaptcha-open(?:-[a-z]+)?\.aliyuncs\.com/i,
      /\bcf\.aliyun\.com\/nocaptcha/i,
      [/\bg\.alicdn\.com\/AWSC\//i, 0.7],
      [/\b[a-z]\.alicdn\.com\/captcha-frontend\//i, 0.9],
    ],
    elements: [
      '#nc_1_wrapper',
      '.nc-container',
      '.nc_wrapper',
      '.nc_scale',
      '#aliyunCaptcha-window-popup',
      '#aliyunCaptcha-sliding-wrapper',
      ['[id^="aliyunCaptcha"]', 0.9],
      ['#nocaptcha', 0.75],
    ],
    globals: ['initAliyunCaptcha', ['noCaptcha', 0.7], ['AWSC', 0.6]],
    urls: [[/\/_____tmd_____\/punish/i, 0.95]],
    text: [[/请按住滑块，?拖动到最右边|please slide to verify/i, 0.8, 'any']],
    refine(d, x) {
      if (/_____tmd_____\/punish/i.test(x.url)) {
        d.kind = 'challenge-page';
        d.visible = true;
      }
      return d;
    },
  },
  {
    id: 'netease-yidun',
    name: 'NetEase Yidun',
    vendor: 'NetEase',
    kind: 'widget',
    subtype: 'slider',
    site: 'https://dun.163.com',
    scripts: [/\bcstaticdun\.126\.net\//i, /\b(?:c|cstatic|webzjcaptcha)\.dun\.163(?:yun)?\.com\//i],
    elements: ['.yidun_slider', '.yidun_panel', '.yidun_popup', ['.yidun', 0.85]],
    globals: ['initNECaptcha', 'initNECaptchaWithFallback'],
  },
  {
    id: 'dingxiang',
    name: 'Dingxiang Captcha',
    vendor: 'Dingxiang',
    kind: 'widget',
    subtype: 'slider',
    site: 'https://www.dingxiang-inc.com',
    scripts: [/\bdingxiang-inc\.com\//i],
    elements: ['.dx_captcha', ['[class*="dx_captcha"]', 0.85]],
    globals: [['_dx', 0.6]],
  },
  {
    id: 'shumei',
    name: 'Shumei Captcha',
    vendor: 'Shumei',
    kind: 'widget',
    subtype: 'slider',
    site: 'https://www.ishumei.com',
    scripts: [/\bcastatic\.fengkongcloud\.(?:com|cn)\//i, [/\bsmcp(?:\.min)?\.js/i, 0.85], [/\bfengkongcloud\.(?:com|cn)\//i, 0.6]],
    elements: ['.shumei_captcha_wrapper', ['[class*="shumei_captcha"]', 0.9]],
    globals: ['initSMCaptcha'],
  },
  {
    id: 'vaptcha',
    name: 'VAPTCHA',
    vendor: 'VAPTCHA',
    kind: 'widget',
    site: 'https://www.vaptcha.com',
    scripts: [/\bvaptcha\.(?:com|net)\//i],
    elements: ['.vaptcha-container', '#vaptchaContainer', '[data-vaptcha]'],
    globals: [['vaptcha', 0.8]],
  },
  {
    id: 'luosimao',
    name: 'Luosimao Captcha',
    vendor: 'Luosimao',
    kind: 'widget',
    site: 'https://luosimao.com/service/captcha',
    scripts: [/\bcaptcha\.luosimao\.com\//i],
    frames: [/\bcaptcha\.luosimao\.com\//i],
    elements: ['.l-captcha', 'input[name="luotest_response"]'],
  },
  {
    id: 'lemin',
    name: 'Lemin Captcha',
    vendor: 'Lemin',
    kind: 'widget',
    subtype: 'puzzle',
    site: 'https://www.leminnow.com',
    scripts: [/\b(?:api\.)?leminnow\.com\//i],
    elements: ['#lemin-cropped-captcha', ['[id^="lemin-cropped-captcha"]', 0.9], 'input[name="lemin_challenge_id"]', 'input[name="lemin_answer"]'],
  },
  {
    id: 'captchafox',
    name: 'CaptchaFox',
    vendor: 'CaptchaFox',
    kind: 'widget',
    site: 'https://captchafox.com',
    scripts: [/\b(?:cdn|api|s)\.captchafox\.com\//i, /@captchafox\//i],
    frames: [/\bcaptchafox\.com\//i],
    elements: ['.captchafox', ['[data-captchafox-sitekey]', 0.9]],
    globals: [['captchafox', 0.85]],
  },
  {
    id: 'procaptcha',
    name: 'Procaptcha',
    vendor: 'Prosopo',
    kind: 'widget',
    site: 'https://prosopo.io',
    scripts: [/\bjs\.prosopo\.io\//i, /@prosopo\//i, [/\bprocaptcha(?:\.bundle)?\.js/i, 0.9]],
    elements: ['.procaptcha', 'input[name="procaptcha-response"]'],
    globals: [['procaptcha', 0.8]],
  },
  {
    id: 'keycaptcha',
    name: 'KeyCAPTCHA',
    vendor: 'KeyCAPTCHA',
    kind: 'widget',
    subtype: 'puzzle',
    site: 'https://www.keycaptcha.com',
    scripts: [/\bkeycaptcha\.com\//i],
    elements: ['#div_for_keycaptcha', ['[id*="keycaptcha" i]', 0.8]],
    inline: [/\bs_s_c_(?:user_id|session_id|web_server_sign)\b/],
    globals: ['s_s_c_user_id'],
  },
  {
    id: 'capy',
    name: 'Capy Puzzle CAPTCHA',
    vendor: 'Capy',
    kind: 'widget',
    subtype: 'puzzle',
    site: 'https://www.capy.me',
    scripts: [/\bcapy\.me\//i],
    frames: [/\bcapy\.me\//i],
    elements: ['.capy-captcha', 'input[name="capy_captchakey"]', 'input[name="capy_challengekey"]', 'input[name="capy_answer"]'],
  },
  {
    id: 'solvemedia',
    name: 'Solve Media',
    vendor: 'Solve Media',
    kind: 'image',
    site: 'https://www.solvemedia.com',
    scripts: [/\bsolvemedia\.com\//i],
    frames: [/\bsolvemedia\.com\//i],
    elements: ['#adcopy-outer', 'input[name="adcopy_response"]', '#adcopy_response', 'input[name="adcopy_challenge"]'],
    globals: ['ACPuzzle'],
  },
  {
    id: 'cutcaptcha',
    name: 'Cutcaptcha',
    vendor: 'Cutcaptcha',
    kind: 'widget',
    subtype: 'puzzle',
    site: 'https://www.cutcaptcha.com',
    scripts: [/\bcutcaptcha\.(?:net|com)\//i],
    frames: [/\bcutcaptcha\.(?:net|com)\//i],
    elements: [['#puzzle-captcha', 0.7], ['input[name="cap_token"]', 0.5]],
    inline: [/\bCUTCAPTCHA_MISERY_KEY\b/],
    globals: ['CUTCAPTCHA_MISERY_KEY'],
  },
  {
    id: 'cybersiara',
    name: 'CyberSiARA',
    vendor: 'CyberSiARA',
    kind: 'widget',
    subtype: 'slider',
    site: 'https://www.cybersiara.com',
    scripts: [/\b(?:embed\.)?mycybersiara\.com\//i, /\bcybersiara\.com\//i],
    elements: [['.SiaraShield', 0.85], ['[class*="SiaraShield"]', 0.8]],
    inline: [[/\bSiaraShield\b|\bCyberSiara\b/i, 0.4]],
  },
  {
    id: 'atbcaptcha',
    name: 'atbCAPTCHA',
    vendor: 'aisecurius',
    kind: 'widget',
    site: 'https://www.aisecurius.com',
    scripts: [/\baisecurius\.com\//i],
    inline: [[/\batbCaptcha\b|\batb-captcha\b/i, 0.4]],
  },
  {
    id: 'mcaptcha',
    name: 'mCaptcha',
    vendor: 'mCaptcha',
    kind: 'widget',
    subtype: 'proof-of-work',
    site: 'https://mcaptcha.org',
    scripts: [/@mcaptcha\//i, [/\bmcaptcha\b/i, 0.7]],
    frames: [[/\bmcaptcha\b/i, 0.75], [/\/widget\/?\?sitekey=/i, 0.6]],
    elements: ['#mcaptcha__widget-container', ['[id^="mcaptcha"]', 0.85], ['.mcaptcha', 0.8]],
  },
  {
    id: 'altcha',
    name: 'ALTCHA',
    vendor: 'ALTCHA',
    kind: 'widget',
    subtype: 'proof-of-work',
    site: 'https://altcha.org',
    scripts: [/altcha-org\/altcha/i, /\baltcha(?:\.min)?\.(?:js|umd\.cjs)/i, [/\baltcha\b/i, 0.6]],
    elements: ['altcha-widget', ['input[name="altcha"]', 0.8]],
  },
  {
    id: 'cap',
    name: 'Cap',
    vendor: 'Cap (open source)',
    kind: 'widget',
    subtype: 'proof-of-work',
    site: 'https://capjs.js.org',
    scripts: [/@cap\.js\/widget/i, [/\bcap(?:\.min)?\.js\b/i, 0.3]],
    elements: ['cap-widget', ['input[name="cap-token"]', 0.8]],
  },
  {
    id: 'private-captcha',
    name: 'Private Captcha',
    vendor: 'Private Captcha',
    kind: 'widget',
    subtype: 'proof-of-work',
    site: 'https://privatecaptcha.com',
    scripts: [/\bprivatecaptcha\.com\//i],
    elements: [['.private-captcha', 0.85], ['input[name="private-captcha-solution"]', 0.9]],
  },
  {
    id: 'trustcaptcha',
    name: 'TrustCaptcha',
    vendor: 'TrustComponent',
    kind: 'widget',
    site: 'https://www.trustcomponent.com',
    scripts: [/\btrustcomponent\.com\//i, /@trustcomponent\//i],
    elements: ['trustcaptcha-component'],
  },
  {
    id: 'mosparo',
    name: 'mosparo',
    vendor: 'mosparo (open source)',
    kind: 'widget',
    site: 'https://mosparo.io',
    scripts: [/mosparo-frontend(?:\.min)?\.js/i, [/\bmosparo\b/i, 0.6]],
    elements: ['.mosparo__container', ['[id^="mosparo-box"]', 0.9], ['[class*="mosparo__"]', 0.85]],
    globals: [['mosparo', 0.7]],
  },
  {
    id: 'botpoison',
    name: 'Botpoison',
    vendor: 'Botpoison',
    kind: 'invisible',
    subtype: 'proof-of-work',
    site: 'https://botpoison.com',
    scripts: [/@botpoison\//i, /\bbotpoison\.com\//i],
    elements: [['[data-botpoison-public-key]', 0.9]],
    globals: [['Botpoison', 0.8]],
  },
  {
    id: 'botdetect',
    name: 'BotDetect CAPTCHA',
    vendor: 'Captcha Inc.',
    kind: 'image',
    site: 'https://captcha.com',
    scripts: [[/botdetect/i, 0.8]],
    elements: [
      '.BDC_CaptchaDiv',
      '.BDC_CaptchaImageDiv',
      ['[class*="BDC_Captcha"]', 0.9],
      { sel: 'img', attr: ['src'], re: /botdetectcaptcha|simple-captcha-endpoint/i, w: 0.95 },
    ],
    globals: [['BotDetect', 0.8]],
  },
  {
    id: 'securimage',
    name: 'Securimage / SI CAPTCHA',
    vendor: 'Securimage',
    kind: 'image',
    site: 'https://www.phpcaptcha.org',
    elements: [{ sel: 'img', attr: ['src', 'id'], re: /securimage|si_image/i, w: 0.95 }, ['input[name="captcha_code"]', 0.45]],
  },
  {
    id: 'wpcf7-captcha',
    name: 'Really Simple CAPTCHA (Contact Form 7)',
    vendor: 'Contact Form 7',
    kind: 'image',
    site: 'https://wordpress.org/plugins/really-simple-captcha/',
    elements: ['.wpcf7-captchac', ['.wpcf7-captchar', 0.9], { sel: 'img', attr: ['src'], re: /wpcf7_captcha/i, w: 0.95 }],
  },
  {
    id: 'wpcf7-quiz',
    name: 'Contact Form 7 Quiz',
    vendor: 'Contact Form 7',
    kind: 'question',
    site: 'https://contactform7.com/quiz/',
    elements: ['.wpcf7-quiz', ['input[name="_wpcf7_quiz_answer_your-quiz"]', 0.9], ['.wpcf7-quiz-label', 0.9]],
  },

  // ───────────────────────────── Bot-check and challenge pages ─────────────────────────────
  {
    id: 'cloudflare-challenge',
    name: 'Cloudflare challenge page',
    vendor: 'Cloudflare',
    kind: 'challenge-page',
    site: 'https://developers.cloudflare.com/waf/reference/cloudflare-challenges/',
    // "Attention Required! | Cloudflare" is used by both the old captcha page and the block page: the text decides.
    title: [[/^just a moment\.{0,3}$/i, 0.8], [/^one more step!? \| cloudflare$/i, 0.6]],
    inline: [[/\bwindow\._cf_chl_opt\b|\b_cf_chl_opt\s*=/, 0.95], [/\bcf_chl_(?:prog|jschl_tk|captcha_tk|managed_tk|rc_[im]|f_tk)\b/, 0.9], [/\bjschl_(?:vc|answer)\b/, 0.9]],
    scripts: [[/\/cdn-cgi\/challenge-platform\/(?:h\/[a-z]\/)?orchestrate\/(?:chl_page|jsch|captcha|managed|chl_api)\//i, 0.95]],
    elements: [
      '#challenge-form',
      '#challenge-running',
      '#challenge-stage',
      '#challenge-body-text',
      '#challenge-error-text',
      '#cf-challenge-running',
      '#cf-please-wait',
      '.cf-browser-verification',
      '#trk_jschal_js',
      { sel: 'form', attr: ['action'], re: /__cf_chl_(?:f|jschl|captcha|managed|rt)_tk/i, w: 0.95 },
    ],
    urls: [[/[?&]__cf_chl_(?:rt|f|jschl|captcha|managed|tk)_tk=/i, 0.9]],
    headers: [['cf-mitigated', /challenge/i, 0.95], ['server', /cloudflare/i, 0.15]],
    status: [403, 503, 429],
    text: [
      [/checking if the site connection is secure/i, 0.85],
      [/needs to review the security of your connection before proceeding/i, 0.85],
      [/verify you are human by completing the action below/i, 0.85],
      [/checking your browser before accessing/i, 0.7],
      [/ddos protection by cloudflare/i, 0.8],
      [/please complete the security check to access/i, 0.75],
      [/enable javascript and cookies to continue/i, 0.6],
      [/performance (?:&|and) security by cloudflare/i, 0.35],
    ],
    refine(d, x) {
      // 'Performance & security by Cloudflare' and the server header alone are on every Cloudflare error page.
      if (d.confidence < 0.6) return null;
      d.subtype = x.has('turnstile') ? 'turnstile' : 'js-challenge';
      return d;
    },
  },
  {
    id: 'cloudflare-block',
    name: 'Cloudflare block page',
    vendor: 'Cloudflare',
    kind: 'block-page',
    site: 'https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/',
    title: [[/attention required! \| cloudflare/i, 0.5], [/access denied \| .* used cloudflare to restrict access/i, 0.9]],
    elements: ['#cf-error-details', '.cf-error-details', '[data-translate="blocked_why_headline"]', ['#cf-wrapper', 0.7]],
    text: [[/sorry, you have been blocked/i, 0.75], [/you are unable to access/i, 0.55], [/cloudflare ray id/i, 0.4]],
    refine(d, x) {
      if (x.has('cloudflare-challenge') || d.confidence < 0.6) return null;
      return d;
    },
  },
  {
    id: 'google-sorry',
    name: 'Google unusual traffic page',
    vendor: 'Google',
    kind: 'challenge-page',
    subtype: 'recaptcha',
    site: 'https://support.google.com/websearch/answer/86640',
    urls: [[/\bgoogle\.[a-z.]+\/sorry\//i, 0.95]],
    elements: [['form#captcha-form', 0.7], { sel: 'form', attr: ['action'], re: /\/sorry\/index/i, w: 0.9 }],
    text: [[/our systems have detected unusual traffic from your computer network/i, 0.95]],
  },
  {
    id: 'amazon-captcha',
    name: 'Amazon robot check',
    vendor: 'Amazon',
    kind: 'challenge-page',
    subtype: 'text-image',
    site: 'https://www.amazon.com',
    elements: [{ sel: 'form', attr: ['action'], re: /\/errors\/validateCaptcha/i, w: 0.95 }, { sel: 'img', attr: ['src'], re: /ssl-images-amazon\.com\/captcha\//i, w: 0.9 }],
    text: [[/enter the characters you see below/i, 0.75], [/type the characters you see in this image/i, 0.7], [/sorry, we just need to make sure you(?:'|’)re not a robot/i, 0.85]],
  },
  {
    id: 'datadome',
    name: 'DataDome',
    vendor: 'DataDome',
    kind: 'protection',
    site: 'https://datadome.co',
    scripts: [/\bjs\.datadome\.co\//i, [/\bdatadome\.co\//i, 0.8], [/\btags\.js\?.*datadome/i, 0.8]],
    inline: [[/\bddjskey\b|\bddoptions\b/, 0.8]],
    cookies: [['datadome', 0.7]],
    headers: [['x-datadome', /./, 0.85], ['x-dd-b', /./, 0.7], ['x-datadome-cid', /./, 0.85]],
    refine(d, x) {
      return x.has('datadome-captcha') ? null : d;
    },
  },
  {
    id: 'datadome-captcha',
    name: 'DataDome captcha',
    vendor: 'DataDome',
    kind: 'challenge-page',
    site: 'https://datadome.co',
    frames: [/\bgeo\.captcha-delivery\.com\/(?:captcha|interstitial)\//i, [/\bcaptcha-delivery\.com\//i, 0.9]],
    scripts: [/\bct\.captcha-delivery\.com\//i, [/\bcaptcha-delivery\.com\//i, 0.85]],
    inline: [[/\bvar dd\s*=\s*\{[^}]*['"]?(?:rt|cid|hsh)['"]?\s*:/, 0.9]],
    globals: [[(w) => !!(w.dd && typeof w.dd === 'object' && !w.dd.nodeType && (w.dd.cid || w.dd.hsh) && w.dd.rt), 0.9]],
    elements: [['iframe[title*="DataDome" i]', 0.9]],
    refine(d, x) {
      const interstitial = x.frames(/\/interstitial\//i).length > 0 || /['"]?rt['"]?\s*:\s*['"]i['"]/.test(x.inline) || x.global('dd.rt') === 'i';
      d.subtype = interstitial ? 'interstitial' : 'slider';
      if (!x.short && !interstitial) {
        // A captcha frame inside a normal page: the overlay variant.
        d.kind = 'widget';
        d.visible = x.anyVisible(x.frames(/captcha-delivery\.com/i));
      } else d.visible = true;
      return d;
    },
  },
  {
    id: 'perimeterx',
    name: 'HUMAN (PerimeterX)',
    vendor: 'HUMAN Security',
    kind: 'protection',
    site: 'https://www.humansecurity.com',
    scripts: [/\bclient\.(?:perimeterx\.net|px-cdn\.net|px-cloud\.net)\//i, /\b(?:collector-)?px[a-z0-9]*\.(?:perimeterx\.net|px-cdn\.net|px-cloud\.net)\//i, [/\/px[a-z0-9]{6,10}\/init\.js/i, 0.85], [/\bperimeterx\.net\//i, 0.85]],
    inline: [[/\bwindow\._pxAppId\s*=|\b_pxAppId\s*=/, 0.85]],
    globals: [['_pxAppId', 0.85]],
    cookies: [['_px3', 0.65], ['_pxhd', 0.6], ['_pxvid', 0.6], ['pxcts', 0.5], ['_pxff_', 0.5]],
    refine(d, x) {
      return x.has('perimeterx-captcha') ? null : d;
    },
  },
  {
    id: 'perimeterx-captcha',
    name: 'HUMAN (PerimeterX) press & hold',
    vendor: 'HUMAN Security',
    kind: 'challenge-page',
    subtype: 'press-and-hold',
    site: 'https://www.humansecurity.com',
    elements: ['#px-captcha', '#px-captcha-wrapper', '.px-captcha-container', ['[id^="px-captcha"]', 0.9]],
    scripts: [/\bcaptcha\.(?:px-cdn|px-cloud)\.net\//i, [/\/captcha\/captcha\.js\?a=c/i, 0.85]],
    frames: [[/\bcaptcha\.(?:px-cdn|px-cloud)\.net\//i, 0.9]],
    inline: [[/\b_pxCaptcha|\bwindow\._pxBlockedUrl\b|\b_pxUuid\s*=/, 0.8]],
    title: [[/^access to this page has been denied\.?$/i, 0.7]],
    text: [[/press (?:&|and) hold to confirm you are(?: a)? human/i, 0.9], [/press (?:&|and) hold/i, 0.5]],
    refine(d, x) {
      if (x.short || d.kind !== 'challenge-page') d.visible = true;
      if (!x.short) {
        d.kind = 'widget';
        d.visible = x.anyVisible(x.query('#px-captcha'));
      }
      return d;
    },
  },
  {
    id: 'akamai-bot-manager',
    name: 'Akamai Bot Manager',
    vendor: 'Akamai',
    kind: 'protection',
    site: 'https://www.akamai.com/products/bot-manager',
    scripts: [[/\/akam\/\d+\/[a-z0-9]+/i, 0.8]],
    inline: [[/\bbmak\.(?:js_post|sensor_data|startTracking)\b/, 0.8]],
    globals: [['bmak', 0.8]],
    cookies: [['_abck', 0.7], ['bm_sz', 0.65], ['ak_bmsc', 0.6], ['bm_sv', 0.5], ['bm_mi', 0.5]],
    refine(d, x) {
      return x.has('akamai-challenge') ? null : d;
    },
  },
  {
    id: 'akamai-challenge',
    name: 'Akamai challenge page',
    vendor: 'Akamai',
    kind: 'challenge-page',
    site: 'https://www.akamai.com/products/bot-manager',
    elements: ['#sec-if-cpt-container', '#sec-cpt-if', ['#sec-text-container', 0.8], ['#sec-container', 0.6]],
    scripts: [/\/_sec\/cp_challenge\//i],
    frames: [/\/_sec\/cp_challenge\//i],
    inline: [[/\/_sec\/(?:cp_challenge|verify)/i, 0.85], [/\bsec-if-cpt\b|\bsec_cpt\b/i, 0.8]],
    text: [[/powered and protected by akamai/i, 0.6]],
  },
  {
    id: 'akamai-block',
    name: 'Akamai access denied',
    vendor: 'Akamai',
    kind: 'block-page',
    site: 'https://www.akamai.com',
    title: [[/^access denied$/i, 0.45]],
    text: [[/you don(?:'|’)t have permission to access/i, 0.6], [/reference\s*#\s*\d+\.[0-9a-f]+\.\d+\.[0-9a-f]+/i, 0.9], [/errors\.edgesuite\.net/i, 0.9, 'any']],
    elements: [{ sel: 'a', attr: ['href'], re: /errors\.edgesuite\.net/i, w: 0.9 }],
    headers: [['server', /akamaighost/i, 0.35]],
    refine(d, x) {
      return d.confidence < 0.6 ? null : d;
    },
  },
  {
    id: 'imperva',
    name: 'Imperva (Incapsula)',
    vendor: 'Imperva',
    kind: 'protection',
    site: 'https://www.imperva.com/products/advanced-bot-protection-management/',
    scripts: [[/\/_Incapsula_Resource\?/i, 0.85]],
    cookies: [['incap_ses_', 0.65], ['visid_incap_', 0.65], ['nlbi_', 0.4], ['reese84', 0.7]],
    headers: [['x-iinfo', /./, 0.7], ['x-cdn', /imperva|incapsula/i, 0.8]],
    refine(d, x) {
      return x.has('imperva-challenge') || x.has('imperva-abp') ? null : d;
    },
  },
  {
    id: 'imperva-challenge',
    name: 'Imperva (Incapsula) challenge page',
    vendor: 'Imperva',
    kind: 'challenge-page',
    site: 'https://www.imperva.com',
    frames: [[/\/_Incapsula_Resource\?/i, 0.9]],
    elements: [{ sel: 'iframe', attr: ['src'], re: /_Incapsula_Resource/i, w: 0.9 }],
    text: [[/request unsuccessful\.? incapsula incident id/i, 0.9], [/incapsula incident id/i, 0.85], [/additional security check is required/i, 0.6]],
    inline: [[/_Incapsula_Resource\?SWUDNSAI/i, 0.85]],
  },
  {
    id: 'imperva-abp',
    name: 'Imperva Advanced Bot Protection (Distil)',
    vendor: 'Imperva',
    kind: 'challenge-page',
    site: 'https://www.imperva.com/products/advanced-bot-protection-management/',
    title: [[/^pardon our interruption\.{0,3}$/i, 0.85]],
    text: [[/something about your browser made us think you were a bot/i, 0.9]],
    inline: [[/\bdistil_(?:r_captcha|r_blocked|identify_cookie)\b/i, 0.8]],
    cookies: [[/^D_(?:IID|UID|ZID|ZUID|HID|SID)$/, 0.45]],
  },
  {
    id: 'kasada',
    name: 'Kasada',
    vendor: 'Kasada',
    kind: 'protection',
    site: 'https://www.kasada.io',
    scripts: [[new RegExp(`/${UUID}/${UUID}/(?:ips|p)\\.js`, 'i'), 0.9]],
    inline: [[/\bKPSDK\b/, 0.85]],
    globals: [['KPSDK', 0.9]],
    headers: [['x-kpsdk-ct', /./, 0.8], ['x-kpsdk-cd', /./, 0.7], ['x-kpsdk-v', /./, 0.7], ['x-kpsdk-r', /./, 0.7]],
    cookies: [['KP_UIDz', 0.6], ['KP_UIDz-ssn', 0.6]],
    refine(d, x) {
      if (x.status === 429 || (x.dom === false && x.textLength < 200 && /ips\.js/.test(d.evidence.map((e) => e.value).join(' ')))) {
        d.kind = 'challenge-page';
        d.subtype = 'silent-challenge';
        d.visible = true;
      }
      return d;
    },
  },
  {
    id: 'f5-asm',
    name: 'F5 BIG-IP ASM',
    vendor: 'F5',
    kind: 'block-page',
    site: 'https://www.f5.com/products/big-ip-services/advanced-waf',
    text: [[/the requested url was rejected\.? please consult with your administrator/i, 0.95], [/your support id is:?\s*\d+/i, 0.6], [/what code is in the image\??/i, 0.8]],
    cookies: [[/^TS[0-9a-f]{6,8}(?:_\d+)?$/, 0.35]],
    refine(d, x) {
      if (/what code is in the image/i.test(x.text)) {
        d.name = 'F5 BIG-IP ASM CAPTCHA';
        d.kind = 'challenge-page';
        d.subtype = 'text-image';
        d.visible = true;
      } else if (d.confidence < 0.6) {
        d.kind = 'protection';
      }
      return d;
    },
  },
  {
    id: 'sucuri',
    name: 'Sucuri Website Firewall',
    vendor: 'Sucuri',
    kind: 'protection',
    site: 'https://sucuri.net/website-firewall/',
    title: [[/sucuri website firewall/i, 0.9]],
    text: [[/sucuri website firewall/i, 0.8]],
    inline: [[/\bsucuri_cloudproxy_js\b/, 0.95]],
    headers: [['x-sucuri-id', /./, 0.7], ['x-sucuri-cache', /./, 0.5], ['server', /sucuri|cloudproxy/i, 0.6]],
    cookies: [['sucuri_cloudproxy_uuid_', 0.5]],
    refine(d, x) {
      if (/sucuri_cloudproxy_js/.test(x.inline)) {
        d.kind = 'challenge-page';
        d.subtype = 'js-challenge';
        d.visible = true;
      } else if (/access denied/i.test(x.title + ' ' + x.text) && x.short) {
        d.kind = 'block-page';
      }
      return d;
    },
  },
  {
    id: 'ddos-guard',
    name: 'DDoS-Guard',
    vendor: 'DDoS-Guard',
    kind: 'protection',
    site: 'https://ddos-guard.net',
    scripts: [[/\bcheck\.ddos-guard\.net\//i, 0.95], [/\/\.well-known\/ddos-guard\//i, 0.9]],
    title: [[/^ddos-guard$/i, 0.85]],
    elements: [['#ddg-captcha', 0.85], ['[id^="ddg-"]', 0.5]],
    headers: [['server', /ddos-guard/i, 0.6]],
    cookies: [['__ddg1_', 0.55], ['__ddg2_', 0.55], ['__ddgid_', 0.55], ['__ddgmark_', 0.55], ['__ddg_', 0.5]],
    refine(d, x) {
      if (d.evidence.some((e) => e.type === 'title' || e.type === 'elements' || /check\.ddos-guard|well-known\/ddos-guard/i.test(e.value))) {
        d.kind = 'challenge-page';
        d.visible = true;
      }
      return d;
    },
  },
  {
    id: 'qrator',
    name: 'Qrator',
    vendor: 'Qrator Labs',
    kind: 'protection',
    site: 'https://qrator.net',
    scripts: [[/\/__qrator\//i, 0.9]],
    headers: [['server', /qrator/i, 0.7]],
    refine(d, x) {
      if (x.short && d.evidence.some((e) => e.type === 'scripts')) {
        d.kind = 'challenge-page';
        d.visible = true;
      }
      return d;
    },
  },
  {
    id: 'stormwall',
    name: 'StormWall',
    vendor: 'StormWall',
    kind: 'protection',
    site: 'https://stormwall.network',
    scripts: [[/\bstormwall\.pro\//i, 0.9]],
    title: [[/stormwall/i, 0.7]],
    inline: [[/\bstormwall\b/i, 0.6]],
    cookies: [['swp_token', 0.6]],
    refine(d, x) {
      if (x.short && d.confidence > 0.7) {
        d.kind = 'challenge-page';
        d.visible = true;
      }
      return d;
    },
  },
  {
    id: 'reblaze',
    name: 'Reblaze',
    vendor: 'Reblaze',
    kind: 'protection',
    site: 'https://www.reblaze.com',
    cookies: [['rbzid', 0.7], ['rbzsessionid', 0.6]],
    headers: [['server', /reblaze/i, 0.8]],
    inline: [[/\brbzns\b/, 0.75]],
    refine(d, x) {
      if (x.short && /\brbzns\b/.test(x.inline)) {
        d.kind = 'challenge-page';
        d.visible = true;
      }
      return d;
    },
  },
  {
    id: 'radware',
    name: 'Radware Bot Manager (ShieldSquare)',
    vendor: 'Radware',
    kind: 'protection',
    site: 'https://www.radware.com/products/bot-manager/',
    scripts: [[/\b(?:cdn|validate)\.perfdrive\.com\//i, 0.9]],
    urls: [[/\bvalidate\.perfdrive\.com\//i, 0.95]],
    title: [[/radware bot manager captcha/i, 0.95]],
    text: [[/radware bot manager/i, 0.7]],
    cookies: [['__uzma', 0.5], ['__uzmb', 0.5], ['__uzmc', 0.5], ['__uzmd', 0.5], ['__ssds', 0.45]],
    refine(d, x) {
      if (/validate\.perfdrive\.com/i.test(x.url) || /radware bot manager/i.test(x.title) || (x.short && /radware bot manager/i.test(x.text))) {
        d.kind = 'challenge-page';
        d.visible = true;
      }
      return d;
    },
  },
  {
    id: 'netacea',
    name: 'Netacea',
    vendor: 'Netacea',
    kind: 'protection',
    site: 'https://netacea.com',
    cookies: [[/^_mitata/, 0.6]],
    scripts: [[/\bnetacea\.com\//i, 0.8]],
  },
  {
    id: 'vercel-challenge',
    name: 'Vercel Security Checkpoint',
    vendor: 'Vercel',
    kind: 'challenge-page',
    site: 'https://vercel.com/docs/vercel-firewall',
    title: [[/vercel security checkpoint/i, 0.95]],
    scripts: [[/\/\.well-known\/vercel\/security\//i, 0.95]],
    headers: [['x-vercel-mitigated', /challenge/i, 0.95]],
    text: [[/we(?:'|’)re verifying your browser/i, 0.7]],
  },
  {
    id: 'anubis',
    name: 'Anubis',
    vendor: 'Techaro (open source)',
    kind: 'challenge-page',
    subtype: 'proof-of-work',
    site: 'https://anubis.techaro.lol',
    title: [[/making sure you(?:'|’)re not a bot!?/i, 0.9]],
    elements: ['#anubis_challenge', '#anubis_version', ['[id^="anubis_"]', 0.8]],
    scripts: [/\/\.within\.website\/x\/cmd\/anubis\//i],
    text: [[/protected by anubis/i, 0.7]],
    cookies: [[/anubis-auth/i, 0.6]],
  },
  {
    id: 'sg-captcha',
    name: 'SiteGround SG-Captcha',
    vendor: 'SiteGround',
    kind: 'challenge-page',
    site: 'https://www.siteground.com',
    urls: [[/\/\.well-known\/sgcaptcha\//i, 0.95]],
    scripts: [[/\/\.well-known\/sgcaptcha\//i, 0.95]],
    frames: [[/\/\.well-known\/sgcaptcha\//i, 0.95]],
    inline: [[/\.well-known\/sgcaptcha/i, 0.9]],
    title: [[/robot challenge screen/i, 0.7]],
  },
  {
    id: 'litespeed-recaptcha',
    name: 'LiteSpeed reCAPTCHA',
    vendor: 'LiteSpeed',
    kind: 'challenge-page',
    site: 'https://docs.litespeedtech.com/lsws/cp/cpanel/antibot/',
    urls: [[/\/\.lsrecap\//i, 0.95]],
    inline: [[/\/\.lsrecap\/recaptcha/i, 0.95]],
    elements: [{ sel: 'form', attr: ['action'], re: /\.lsrecap/i, w: 0.95 }],
  },
  {
    id: 'imunify360',
    name: 'Imunify360 bot protection',
    vendor: 'CloudLinux',
    kind: 'challenge-page',
    site: 'https://www.imunify360.com',
    text: [[/access denied by imunify360 bot-protection/i, 0.95], [/imunify360/i, 0.7]],
    title: [[/imunify360/i, 0.8]],
    scripts: [[/imunify360/i, 0.8]],
  },
  {
    id: 'bitninja',
    name: 'BitNinja captcha',
    vendor: 'BitNinja',
    kind: 'challenge-page',
    site: 'https://bitninja.com',
    text: [[/security check by bitninja/i, 0.95], [/bitninja/i, 0.65]],
    title: [[/bitninja/i, 0.75]],
  },
  {
    id: 'wordfence',
    name: 'Wordfence block page',
    vendor: 'Defiant',
    kind: 'block-page',
    site: 'https://www.wordfence.com',
    text: [[/your access to this site has been limited by the site owner/i, 0.9], [/generated by wordfence/i, 0.8]],
  },
  {
    id: 'yandex-showcaptcha',
    name: 'Yandex robot check',
    vendor: 'Yandex',
    kind: 'challenge-page',
    site: 'https://yandex.com/support/captcha/',
    urls: [[/\/(?:showcaptcha|checkcaptcha)\b/i, 0.8]],
    elements: ['.CheckboxCaptcha', '.AdvancedCaptcha', '#checkbox-captcha-form', { sel: 'form', attr: ['action'], re: /\/checkcaptcha/i, w: 0.9 }],
    text: [[/подтвердите,? что запросы отправляли вы,? а не робот/i, 0.9], [/please confirm that you and not a robot are sending requests/i, 0.9]],
  },
  {
    id: 'vk-captcha',
    name: 'VK captcha',
    vendor: 'VK',
    kind: 'challenge-page',
    site: 'https://vk.com',
    urls: [[/\bid\.vk\.com\/not_robot_captcha|\/not_robot_captcha\b/i, 0.9]],
    elements: [{ sel: 'img', attr: ['src'], re: /\bvk\.com\/captcha\.php|\/captcha\.php\?sid=/i, w: 0.85 }],
    refine(d, x) {
      if (!/not_robot_captcha/i.test(x.url)) {
        d.kind = 'image';
        d.visible = x.anyVisible(x.query('img'), (n) => /captcha\.php/i.test(n.attr('src') || ''));
      }
      return d;
    },
  },
  {
    id: 'baidu-captcha',
    name: 'Baidu security check',
    vendor: 'Baidu',
    kind: 'widget',
    subtype: 'rotate',
    site: 'https://www.baidu.com',
    urls: [[/\bwappass\.baidu\.com\/static\/captcha\//i, 0.95]],
    scripts: [[/\bwappass\.baidu\.com\/static\/captcha/i, 0.9], [/\bppui-static-(?:pc|wap)\.cdn\.bcebos\.com\/.*captcha/i, 0.85]],
    elements: ['.passMod_spin-wrap', ['.vcode-spin', 0.85], ['[class*="vcode-spin"]', 0.8]],
    text: [[/百度安全验证/, 0.9]],
    refine(d, x) {
      if (/wappass\.baidu\.com\/static\/captcha/i.test(x.url) || x.short) {
        d.kind = 'challenge-page';
        d.visible = true;
      }
      return d;
    },
  },

  // ───────────────────────────── Catch-all rules ─────────────────────────────
  {
    id: 'generic-image-captcha',
    name: 'Image captcha',
    vendor: null,
    kind: 'image',
    subtype: 'text-image',
    generic: true,
    elements: [
      {
        sel: 'img',
        attr: ['src', 'id', 'class', 'alt', 'name', 'title'],
        re: CAPTCHA_IMG,
        w: 0.75,
      },
      { sel: 'canvas', attr: ['id', 'class'], re: /captch|verif(?:y|ication)_?code|check_?code/i, w: 0.7 },
      {
        sel: 'input:not([type="hidden"])',
        attr: ['name', 'id', 'placeholder', 'aria-label', 'class'],
        re: /captch|kaptcha|check_?code|verif(?:y|ication)_?code|valid(?:ate)?_?code|(?:^|[^a-z])v_?code|image_?code|img_?code|pic_?code|auth_?code|(?:^|[^a-z])yzm(?:[^a-z]|$)|验证码|驗證碼|認証コード|画像認証|보안 ?문자|자동입력/i,
        w: 0.45,
      },
    ],
    text: [[/(?:enter|type) the (?:characters|code|text|letters|numbers|word)s? (?:you see|shown|displayed|in the (?:image|picture|box))|图形验证码|图片验证码|看不清[，,]?换一张|画像に表示されている文字/i, 0.6, 'any']],
    refine(d, x) {
      const imgs = captchaImages(x);
      const other = d.evidence.some((e) => e.type === 'text' || (e.type === 'elements' && /^input/.test(e.value)));
      if (!(imgs.length && other)) return null;
      d.visible = x.anyVisible(imgs);
      return d;
    },
  },
  {
    id: 'generic-question',
    name: 'Question / math captcha',
    vendor: null,
    kind: 'question',
    generic: true,
    elements: [
      { sel: 'input:not([type="hidden"])', attr: ['name', 'id', 'class', 'placeholder', 'aria-label'], re: /captch|quiz|math|(?:^|[^a-z])sum(?:[^a-z]|$)|security_?(?:question|answer)|antispam|anti-spam|human/i, w: 0.5 },
      { sel: 'input:not([type="hidden"])', attr: ['name', 'id'], re: /text_?captcha|captcha_?(?:answer|question|text)|question_?captcha/i, w: 0.6 },
    ],
    text: [
      [/(?:what is|what's|solve|calculate|how much is|wie viel ist|cuánto es|combien font)\s*:?\s*\d{1,3}\s*(?:\+|plus|-|minus|−|×|x|\*|times)\s*\d{1,3}\s*(?:=\s*)?\??/i, 0.6, 'any'],
      [/\b\d{1,3}\s*(?:\+|−|-|×|x|\*)\s*\d{1,3}\s*=\s*(?:\?|_{2,})/i, 0.55, 'any'],
    ],
    refine(d, x) {
      const input = d.evidence.some((e) => e.type === 'elements');
      const text = d.evidence.some((e) => e.type === 'text');
      // An answer field named like a text captcha, with no captcha image next to it.
      const named = d.evidence.some((e) => e.type === 'elements' && /text_?captcha|captcha_?(?:answer|question|text)|question_?captcha/i.test(e.value));
      const image = captchaImages(x).length > 0;
      if (!(input && text) && !(named && !image)) return null;
      const inputs = x.query('input').filter((n) => /captch|quiz|math|answer/i.test([n.attr('name'), n.attr('id')].join(' ')));
      d.visible = x.anyVisible(inputs);
      return d;
    },
  },
  {
    id: 'generic-slider',
    name: 'Slider captcha',
    vendor: null,
    kind: 'widget',
    subtype: 'slider',
    generic: true,
    elements: [
      { sel: 'div', attr: ['class', 'id'], re: /slider[-_]?captcha|captcha[-_]?slider|slide[-_]?verify|verify[-_]?slide|slide[-_]?captcha|drag[-_]?verify|puzzle[-_]?captcha/i, w: 0.8 },
    ],
    text: [
      [/slide to (?:verify|complete|unlock)|drag the slider|drag the (?:puzzle )?piece|拖动(?:下方)?滑块|向右(?:拖动|滑动)|完成拼图|スライドして認証/i, 0.55, 'any'],
      [/select all (?:images|squares|pictures) with|rotate the (?:image|picture|object) (?:to|until)|click (?:on )?the (?:images?|objects?|icons?) in (?:the )?(?:following|this) order/i, 0.45, 'any'],
    ],
    refine(d, x) {
      d.visible = x.anyVisible(x.query('div'), (n) => /slider[-_]?captcha|captcha[-_]?slider|slide[-_]?verify|verify[-_]?slide|slide[-_]?captcha|drag[-_]?verify|puzzle[-_]?captcha/i.test((n.attr('class') || '') + ' ' + (n.attr('id') || '')));
      return d;
    },
  },
  {
    id: 'generic-captcha',
    name: 'Captcha (unknown provider)',
    vendor: null,
    kind: 'widget',
    generic: true,
    // Needs two signals (or a captcha frame): a page that only talks about captchas has headings and images named so.
    scripts: [[/captcha/i, 0.4]],
    frames: [[/captcha/i, 0.7]],
    elements: [
      ['iframe[title*="captcha" i]', 0.7],
      { sel: 'div', attr: ['id', 'class'], re: /captcha/i, w: 0.4 },
      { sel: 'form', attr: ['id', 'class', 'name', 'action'], re: /captcha/i, w: 0.45 },
      { sel: 'input:not([type="hidden"])', attr: ['name', 'id'], re: /captcha/i, w: 0.45 },
      { sel: 'img', attr: ['src', 'id', 'class'], re: /captcha/i, w: 0.4 },
      { sel: 'canvas', attr: ['id', 'class'], re: /captcha/i, w: 0.45 },
    ],
    refine(d, x) {
      const re = /captcha/i;
      const nodes = ['div', 'form', 'img', 'canvas', 'iframe'].flatMap((t) => x.query(t)).filter((n) => re.test([n.attr('id'), n.attr('class'), n.attr('title'), n.attr('src')].join(' ')));
      d.visible = x.anyVisible(nodes.concat(x.frames(re)));
      return d;
    },
  },
  {
    id: 'generic-challenge',
    name: 'Bot check page',
    vendor: null,
    kind: 'challenge-page',
    generic: true,
    title: [
      [
        /^(?:security check|security verification|bot check|bot verification|human verification|verify(?:ing)? (?:you are |that you are )?(?:a )?human|are you (?:a )?(?:human|robot)\??|captcha|robot check|access check|client challenge|checking your browser|ddos protection|安全验证|安全驗證|人机验证|人機驗證|验证码|驗證碼|проверка|robot challenge screen)\b/i,
        0.55,
      ],
    ],
    text: [
      [
        /\b(?:verify(?:ing)? (?:that )?you(?:'|’)?re? (?:a )?human|verify you are (?:a )?human|are you (?:a )?(?:human|robot)\b|i(?:'|’)?m not a robot|i am not a robot|confirm (?:that )?you(?:'|’)?re? (?:a )?human|confirm you are (?:a )?human|prove (?:that )?you(?:'|’)?re? (?:a )?human|human verification|bot (?:check|verification)|making sure you(?:'|’)re not a bot|checking (?:your|the) browser|please (?:complete|solve) the (?:security )?(?:check|captcha|challenge|puzzle)|complete the security check|press (?:&|and) hold|unusual traffic|automated (?:queries|requests))/i,
        0.6,
      ],
      [
        /no soy un robot|verifica(?:r)? que (?:eres|es) (?:un )?humano|comprobando (?:su|tu) navegador|je ne suis pas un robot|v[ée]rifi(?:ez|er|cation) que vous [êe]tes (?:un )?humain|ich bin kein roboter|best[äa]tigen sie,? dass sie ein mensch sind|n[ãa]o sou um rob[ôo]|confirme que (?:voc[êe] )?[ée] humano|non sono un robot|я не робот|подтвердите,? что (?:вы )?(?:не робот|человек)|проверка (?:браузера|безопасности)|我不是机器人|我不是機器人|人机验证|人機驗證|请完成(?:安全)?验证|請完成(?:安全)?驗證|ロボットではありません|로봇이 아닙니다|tôi không phải là người máy|xác minh (?:rằng )?bạn là (?:con )?người|ben robot değilim|nie jestem robotem|ik ben geen robot|saya bukan robot|أنا لست روبوت|मैं रोबोट नहीं हूं/i,
        0.6,
      ],
    ],
    refine(d, x) {
      return x.short ? d : null;
    },
  },
  {
    id: 'generic-block',
    name: 'Access denied page',
    vendor: null,
    kind: 'block-page',
    generic: true,
    title: [[/^(?:access denied|403 forbidden|forbidden|blocked|request rejected|you have been blocked|error 10(?:0[0-9]|1[0-9]|20))\b/i, 0.55]],
    text: [
      [
        /\b(?:access (?:to this (?:page|site|resource|website) )?(?:has been |is )?denied|you(?: have|(?:'|’)ve) been blocked|your (?:ip|ip address|request|access|connection) (?:has been|was|is) (?:blocked|denied|restricted)|request (?:blocked|rejected)|this request was blocked)\b/i,
        0.55,
      ],
    ],
    status: [403, 429],
    refine(d, x) {
      return x.short ? d : null;
    },
  },
];


const VERSION = '1.0.0';

/** Kinds that mean "there is a captcha / human check on this page". */
const CAPTCHA_KINDS = { widget: 1, invisible: 1, image: 1, question: 1, 'challenge-page': 1 };
const TYPES = ['scripts', 'frames', 'elements', 'inline', 'globals', 'urls', 'title', 'text', 'cookies', 'headers', 'status'];
const DEFAULT_WEIGHT = { scripts: 0.9, frames: 0.95, elements: 0.85, inline: 0.8, globals: 0.85, urls: 0.8, title: 0.65, text: 0.6, cookies: 0.5, headers: 0.75, status: 0.25 };
/** A bot-check page is short: wording only counts on pages with less visible text than this. */
const SHORT_PAGE = 6000;
const MAX_TEXT = 200000;
const MAX_INLINE = 600000;

// ───────────────────────────── Signature compilation ─────────────────────────────

let compiled = null;

function compileEntry(type, e) {
  if (type === 'headers') return { p: [String(e[0]).toLowerCase(), e[1]], w: e[2] };
  if (type === 'status') return { p: e };
  if (Array.isArray(e)) return { p: e[0], w: e[1], any: e[2] === 'any' };
  if (type === 'elements' && e && typeof e === 'object' && e.sel) return { p: e, w: e.w };
  return { p: e };
}

function compile(signatures) {
  return signatures.map((sig) => {
    const c = { sig, m: {} };
    for (const type of TYPES) if (sig[type]) c.m[type] = sig[type].map((e) => compileEntry(type, e));
    return c;
  });
}

function getCompiled(signatures) {
  if (signatures && signatures !== SIGNATURES) return compile(signatures);
  return compiled || (compiled = compile(SIGNATURES));
}

// ───────────────────────────── Small helpers ─────────────────────────────

const short = (s, n = 140) => {
  s = String(s == null ? '' : s).replace(/\s+/g, ' ').trim();
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
};

function lowerHeaders(h) {
  const out = {};
  if (!h) return out;
  const add = (k, v) => {
    k = String(k).toLowerCase();
    v = Array.isArray(v) ? v.join('\n') : String(v);
    out[k] = out[k] ? out[k] + '\n' + v : v;
  };
  if (typeof h.forEach === 'function' && typeof h.get === 'function') {
    h.forEach((v, k) => add(k, v));
    if (typeof h.getSetCookie === 'function') {
      const sc = h.getSetCookie();
      if (sc && sc.length) out['set-cookie'] = sc.join('\n');
    }
  } else if (Array.isArray(h)) h.forEach(([k, v]) => add(k, v));
  else for (const k of Object.keys(h)) if (h[k] != null) add(k, h[k]);
  return out;
}

function cookieNames(input, headers) {
  const names = new Set();
  const fromPairs = (str, sep) =>
    String(str)
      .split(sep)
      .forEach((part) => {
        const name = part.split('=')[0].trim();
        if (name) names.add(name);
      });
  if (typeof input === 'string') fromPairs(input, ';');
  else if (Array.isArray(input)) input.forEach((c) => (typeof c === 'string' ? fromPairs(c, ';') : c && c.name && names.add(c.name)));
  else if (input && typeof input === 'object') Object.keys(input).forEach((k) => names.add(k));
  if (headers && headers['set-cookie']) headers['set-cookie'].split('\n').forEach((line) => fromPairs(line.split(';')[0], ';'));
  return [...names];
}

function getPath(obj, path) {
  try {
    let o = obj;
    for (const k of path.split('.')) {
      if (o == null) return undefined;
      o = o[k];
    }
    return o;
  } catch (_) {
    return undefined;
  }
}

/** A global that is really a DOM element (named access via id="…") does not count. */
function realGlobal(v) {
  return v != null && !(typeof v === 'object' && typeof v.nodeType === 'number');
}

// ───────────────────────────── Mini selector engine (HTML mode) ─────────────────────────────

const selectorCache = new Map();

function parseCompound(src) {
  const c = { tag: null, ids: [], classes: [], attrs: [], nots: [] };
  const re = /\s*(?:(\*|[a-zA-Z][\w-]*)|#([\w-]+)|\.([\w-]+)|\[\s*([\w:-]+)\s*(?:([~^$*|]?=)\s*(?:"([^"]*)"|'([^']*)'|([^\]\s]+))\s*(i)?)?\s*\]|:not\(([^)]*)\))/y;
  let pos = 0;
  src = src.trim();
  while (pos < src.length) {
    re.lastIndex = pos;
    const m = re.exec(src);
    if (!m || m.index !== pos) throw new Error('Unsupported selector: ' + src);
    if (m[1]) c.tag = m[1] === '*' ? null : m[1].toLowerCase();
    else if (m[2]) c.ids.push(m[2]);
    else if (m[3]) c.classes.push(m[3]);
    else if (m[4]) c.attrs.push({ name: m[4].toLowerCase(), op: m[5] || null, value: m[6] != null ? m[6] : m[7] != null ? m[7] : m[8], i: !!m[9] });
    else if (m[10] != null) c.nots.push(parseCompound(m[10]));
    pos = re.lastIndex;
  }
  return c;
}

function parseSelector(sel) {
  let parsed = selectorCache.get(sel);
  if (!parsed) {
    parsed = sel.split(',').map(parseCompound);
    selectorCache.set(sel, parsed);
  }
  return parsed;
}

function attrMatches(a, actual) {
  if (actual == null) return false;
  if (!a.op) return true;
  let v = a.value;
  let s = actual;
  if (a.i) {
    v = v.toLowerCase();
    s = s.toLowerCase();
  }
  switch (a.op) {
    case '=':
      return s === v;
    case '*=':
      return v !== '' && s.includes(v);
    case '^=':
      return v !== '' && s.startsWith(v);
    case '$=':
      return v !== '' && s.endsWith(v);
    case '~=':
      return s.split(/\s+/).includes(v);
    case '|=':
      return s === v || s.startsWith(v + '-');
    default:
      return false;
  }
}

function compoundMatches(c, tag) {
  if (c.tag && c.tag !== tag.tag) return false;
  for (const id of c.ids) if (tag.attrs.id !== id) return false;
  if (c.classes.length) {
    const list = (tag.attrs.class || '').split(/\s+/);
    for (const cl of c.classes) if (!list.includes(cl)) return false;
  }
  for (const a of c.attrs) if (!attrMatches(a, tag.attrs[a.name])) return false;
  for (const n of c.nots) if (compoundMatches(n, tag)) return false;
  return true;
}

// ───────────────────────────── HTML collector ─────────────────────────────

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', '#39': "'" };
function decode(s) {
  return String(s).replace(/&(#x[0-9a-f]+|#\d+|[a-z]+\d*);/gi, (m, e) => {
    if (e[0] === '#') {
      const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      try {
        return String.fromCodePoint(code);
      } catch (_) {
        return m;
      }
    }
    const v = ENTITIES[e.toLowerCase()];
    return v != null ? v : m;
  });
}

function resolveUrl(u, base) {
  if (!u) return '';
  u = u.trim();
  if (!base) return u;
  try {
    return new URL(u, base).href;
  } catch (_) {
    return u;
  }
}

/** Build a page snapshot from an HTML string (no DOM needed: works in Node, workers, anywhere). */
function snapshotFromHtml(html, opts = {}) {
  html = String(html == null ? '' : html);
  const headers = lowerHeaders(opts.headers);
  const noComments = html.replace(/<!--[\s\S]*?-->/g, '');
  let base = opts.url || '';
  const baseTag = /<base\b[^>]*\bhref\s*=\s*["']?([^"'\s>]+)/i.exec(noComments);
  if (baseTag) base = resolveUrl(decode(baseTag[1]), base);

  const inlineParts = [];
  let inlineLen = 0;
  // Pull scripts, styles and other raw-text elements out, so tag parsing does not see markup inside JS strings.
  const stripped = noComments.replace(/<(script|style|template|textarea|noscript|xmp)\b([^>]*)>([\s\S]*?)<\/\1\s*>/gi, (m, tag, attrs, body) => {
    const t = tag.toLowerCase();
    if (t === 'script' && !/\bsrc\s*=/i.test(attrs) && inlineLen < MAX_INLINE) {
      inlineParts.push(body);
      inlineLen += body.length;
    }
    // Keep the opening tag (attributes matter: script src, textarea name), drop the body.
    return `<${tag}${attrs}></${tag}>`;
  });

  const tags = [];
  const tagRe = /<([a-zA-Z][a-zA-Z0-9:-]*)((?:\s+[^\s"'>\/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*)\s*\/?>/g;
  const attrRe = /([^\s"'>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m;
  while ((m = tagRe.exec(stripped))) {
    const attrs = {};
    if (m[2]) {
      let a;
      attrRe.lastIndex = 0;
      while ((a = attrRe.exec(m[2]))) {
        const name = a[1].toLowerCase();
        if (!(name in attrs)) attrs[name] = decode(a[2] != null ? a[2] : a[3] != null ? a[3] : a[4] != null ? a[4] : '');
      }
    }
    tags.push({ tag: m[1].toLowerCase(), attrs });
  }

  const scripts = [];
  const frames = [];
  for (const t of tags) {
    if (t.tag === 'script' && t.attrs.src) scripts.push(resolveUrl(t.attrs.src, base));
    else if (t.tag === 'link' && t.attrs.href && /\b(?:preload|modulepreload|prefetch)\b/i.test(t.attrs.rel || '') && /^(?:script|)$/i.test(t.attrs.as || 'script'))
      scripts.push(resolveUrl(t.attrs.href, base));
    else if ((t.tag === 'iframe' || t.tag === 'frame') && (t.attrs.src || t.attrs['data-src']))
      frames.push({ src: resolveUrl(t.attrs.src || t.attrs['data-src'], base), title: t.attrs.title || '', name: t.attrs.name || '', node: makeHtmlNode(t) });
  }

  const titleM = /<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(noComments);
  const title = titleM ? decode(titleM[1]).replace(/\s+/g, ' ').trim() : '';
  let bodyHtml = stripped.replace(/<head\b[\s\S]*?<\/head\s*>/i, ' ').replace(/<title\b[\s\S]*?<\/title\s*>/gi, ' ');
  const text = decode(bodyHtml.replace(/<(?:br|p|div|li|tr|h[1-6]|section|article|header|footer)\b[^>]*>/gi, '\n').replace(/<[^>]+>/g, ' '))
    .replace(/[ \t\f\v\r ]+/g, ' ')
    .replace(/\s*\n\s*/g, '\n')
    .trim()
    .slice(0, MAX_TEXT);

  const nodeCache = new Map();
  return {
    mode: 'html',
    url: opts.url || '',
    title,
    text,
    textLength: text.replace(/\s+/g, ' ').length,
    scripts,
    resources: [],
    frames,
    inline: inlineParts.join('\n;\n'),
    cookies: cookieNames(opts.cookies, headers),
    headers,
    status: opts.status != null ? Number(opts.status) : null,
    win: null,
    query(sel) {
      let r = nodeCache.get(sel);
      if (!r) {
        const parsed = parseSelector(sel);
        r = tags.filter((t) => parsed.some((c) => compoundMatches(c, t))).map(makeHtmlNode);
        nodeCache.set(sel, r);
      }
      return r;
    },
    isVisible: () => null,
  };
}

function makeHtmlNode(t) {
  return t.node || (t.node = { tag: t.tag, el: null, attr: (n) => (t.attrs[n.toLowerCase()] != null ? t.attrs[n.toLowerCase()] : null) });
}

// ───────────────────────────── DOM collector ─────────────────────────────

/** Is this element shown to the user at a usable size? */
function elementVisible(el) {
  try {
    if (!el || !el.isConnected) return false;
    const doc = el.ownerDocument;
    const win = doc.defaultView;
    if (!win) return false;
    if (typeof el.checkVisibility === 'function' && !el.checkVisibility({ opacityProperty: true, visibilityProperty: true, checkOpacity: true, checkVisibilityCSS: true })) return false;
    const cs = win.getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.visibility === 'collapse' || parseFloat(cs.opacity) < 0.05) return false;
    let r = el.getBoundingClientRect();
    let w = r.width;
    let h = r.height;
    let left = r.left;
    let top = r.top;
    if ((w < 10 || h < 10) && el.children && el.children.length) {
      // A container can be 0×0 while its (positioned) widget is shown: use the children's box.
      let l = Infinity, t = Infinity, rr = -Infinity, b = -Infinity;
      for (const c of el.children) {
        const cr = c.getBoundingClientRect();
        if (cr.width < 1 || cr.height < 1) continue;
        l = Math.min(l, cr.left);
        t = Math.min(t, cr.top);
        rr = Math.max(rr, cr.right);
        b = Math.max(b, cr.bottom);
      }
      if (rr > l && b > t) {
        w = rr - l;
        h = b - t;
        left = l;
        top = t;
      }
    }
    if (w < 10 || h < 10) return false;
    // Pushed off the page (the usual way to hide a challenge until it is needed).
    if (left + w + win.scrollX <= 0 || top + h + win.scrollY <= 0) return false;
    const vw = Math.max(doc.documentElement.scrollWidth, win.innerWidth);
    if (left + win.scrollX >= vw + 50) return false;
    // Inside a same-origin frame: the frame itself must be shown too.
    if (win.frameElement && win.parent !== win) return elementVisible(win.frameElement);
    return true;
  } catch (_) {
    return null;
  }
}

function makeDomNode(el) {
  let tag = '';
  try {
    tag = String(el.localName || el.tagName || el.nodeName || '').toLowerCase();
  } catch (_) {
    /* pages can tamper with DOM prototypes */
  }
  return {
    tag,
    el,
    attr: (n) => {
      try {
        return el.getAttribute(n);
      } catch (_) {
        return null;
      }
    },
  };
}

/** Documents and open shadow roots to search: the page, same-origin frames and open shadow DOM. */
function gatherRoots(doc, deep) {
  const roots = [doc];
  if (!deep) return roots;
  const seen = new Set([doc]);
  for (let i = 0; i < roots.length && roots.length < 200; i++) {
    const root = roots[i];
    let walker;
    try {
      walker = (root.ownerDocument || root).createTreeWalker(root, 1 /* SHOW_ELEMENT */);
    } catch (_) {
      continue;
    }
    let n = 0;
    for (let el = walker.nextNode(); el && n < 60000; el = walker.nextNode(), n++) {
      if (el.shadowRoot && !seen.has(el.shadowRoot)) {
        seen.add(el.shadowRoot);
        roots.push(el.shadowRoot);
      }
      const tag = el.localName;
      if (tag === 'iframe' || tag === 'frame') {
        try {
          const d = el.contentDocument;
          if (d && !seen.has(d) && d.documentElement) {
            seen.add(d);
            roots.push(d);
          }
        } catch (_) {
          /* cross-origin */
        }
      }
    }
  }
  return roots;
}

/** Build a page snapshot from a live window (browser, extension content script, Playwright/Puppeteer evaluate). */
function snapshotFromDom(win, opts = {}) {
  win = win || (typeof window !== 'undefined' ? window : null);
  if (!win || !win.document) throw new Error('captcha-detector: no window/document; use detectHtml() outside a browser');
  const doc = win.document;
  const roots = gatherRoots(doc, opts.deep !== false);
  const all = (sel) => {
    const out = [];
    for (const r of roots) {
      try {
        r.querySelectorAll(sel).forEach((el) => out.push(el));
      } catch (_) {
        /* selector unsupported in this browser */
      }
    }
    return out;
  };

  const scripts = [];
  for (const s of all('script[src]')) {
    try {
      scripts.push(String(s.src || s.getAttribute('src') || ''));
    } catch (_) {
      /* ignore */
    }
  }
  for (const l of all('link[rel~="preload"][href], link[rel~="modulepreload"][href]')) {
    try {
      if (!l.as || l.as === 'script') scripts.push(String(l.href));
    } catch (_) {
      /* ignore */
    }
  }

  const resources = [];
  const addResources = (w) => {
    try {
      const entries = w.performance && w.performance.getEntriesByType ? w.performance.getEntriesByType('resource') : [];
      for (let i = 0; i < entries.length && resources.length < 3000; i++) resources.push({ url: entries[i].name, type: entries[i].initiatorType || '' });
    } catch (_) {
      /* ignore */
    }
  };
  addResources(win);
  for (const r of roots) if (r !== doc && r.nodeType === 9 && r.defaultView) addResources(r.defaultView);

  const frames = all('iframe, frame').map((el) => {
    const node = makeDomNode(el);
    let src = '';
    try {
      src = el.src || '';
    } catch (_) {
      /* ignore */
    }
    return { src: src || node.attr('src') || node.attr('data-src') || '', title: node.attr('title') || '', name: node.attr('name') || '', node, el };
  });

  let inline = '';
  for (const s of all('script:not([src])')) {
    if (inline.length > MAX_INLINE) break;
    inline += (s.textContent || '') + '\n;\n';
  }

  let text = '';
  try {
    text = (doc.body ? doc.body.innerText || doc.body.textContent || '' : '').slice(0, MAX_TEXT);
  } catch (_) {
    /* ignore */
  }
  text = text.replace(/[ \t\f\v\r ]+/g, ' ').replace(/\s*\n\s*/g, '\n').trim();

  let cookieStr = '';
  try {
    cookieStr = doc.cookie || '';
  } catch (_) {
    /* sandboxed */
  }
  const headers = lowerHeaders(opts.headers);

  const nodeCache = new Map();
  const visCache = new Map();
  return {
    mode: 'dom',
    url: (() => {
      try {
        return win.location.href;
      } catch (_) {
        return '';
      }
    })(),
    title: doc.title || '',
    text,
    textLength: text.replace(/\s+/g, ' ').length,
    scripts,
    resources,
    frames,
    inline,
    cookies: cookieNames(cookieStr + (opts.cookies ? ';' + (typeof opts.cookies === 'string' ? opts.cookies : '') : ''), headers),
    headers,
    status: opts.status != null ? Number(opts.status) : null,
    win,
    query(sel) {
      let r = nodeCache.get(sel);
      if (!r) {
        r = all(sel).map(makeDomNode);
        nodeCache.set(sel, r);
      }
      return r;
    },
    isVisible(node) {
      const el = node && node.el;
      if (!el) return null;
      if (!visCache.has(el)) visCache.set(el, elementVisible(el));
      return visCache.get(el);
    },
  };
}

// ───────────────────────────── Matching ─────────────────────────────

/** Resource Timing types that are code or API calls (not images, media or documents). */
const SCRIPT_LIKE = { script: 1, link: 1, xmlhttprequest: 1, fetch: 1, beacon: 1, other: 1, css: 1, '': 1 };

const MATCH = {
  scripts(re, s) {
    for (const u of s.scripts) if (re.test(u)) return { value: u };
    for (const r of s.resources) if (SCRIPT_LIKE[r.type] && re.test(r.url)) return { value: r.url, loaded: true };
    return null;
  },
  frames(re, s) {
    const hit = s.frames.filter((f) => f.src && re.test(f.src));
    if (hit.length) return { value: hit[0].src, nodes: hit.map((f) => f.node) };
    for (const r of s.resources) if ((r.type === 'iframe' || r.type === 'frame') && re.test(r.url)) return { value: r.url, loaded: true };
    return null;
  },
  elements(p, s) {
    if (typeof p === 'string') {
      const nodes = s.query(p);
      return nodes.length ? { value: p, nodes } : null;
    }
    const nodes = s.query(p.sel).filter((n) => p.attr.some((a) => {
      const v = n.attr(a);
      return v != null && p.re.test(v);
    }));
    if (!nodes.length) return null;
    const n = nodes[0];
    const a = p.attr.find((x) => n.attr(x) != null && p.re.test(n.attr(x)));
    return { value: `${p.sel}[${a}="${short(n.attr(a), 80)}"]`, nodes };
  },
  inline(re, s) {
    const m = re.exec(s.inline);
    return m ? { value: m[0] } : null;
  },
  globals(p, s) {
    if (!s.win) return null;
    try {
      if (typeof p === 'function') return p(s.win) ? { value: 'window check' } : null;
      return realGlobal(getPath(s.win, p)) ? { value: 'window.' + p } : null;
    } catch (_) {
      return null;
    }
  },
  urls(re, s) {
    return s.url && re.test(s.url) ? { value: s.url } : null;
  },
  title(re, s) {
    return s.title && re.test(s.title) ? { value: s.title } : null;
  },
  text(re, s, entry) {
    if (!entry.any && s.textLength > SHORT_PAGE) return null;
    const m = re.exec(s.text);
    return m ? { value: m[0] } : null;
  },
  cookies(p, s) {
    const name = s.cookies.find((c) => (typeof p === 'string' ? (/[_-]$/.test(p) ? c.startsWith(p) : c === p) : p.test(c)));
    return name ? { value: name } : null;
  },
  headers(p, s) {
    const v = s.headers[p[0]];
    return v != null && p[1].test(v) ? { value: `${p[0]}: ${short(v, 60)}` } : null;
  },
  status(p, s) {
    return s.status === p ? { value: String(p) } : null;
  },
};

function scoreSignature(c, s) {
  const evidence = [];
  const nodes = [];
  for (const type of TYPES) {
    const list = c.m[type];
    if (!list) continue;
    for (const entry of list) {
      let r = null;
      try {
        r = MATCH[type](entry.p, s, entry);
      } catch (_) {
        r = null;
      }
      if (!r) continue;
      const w = entry.w != null ? entry.w : DEFAULT_WEIGHT[type];
      const value = short(r.value);
      const same = evidence.find((e) => e.type === type && e.value === value);
      // Two patterns that hit the same thing are one piece of evidence.
      if (same) same.weight = Math.max(same.weight, w);
      else evidence.push({ type, value, weight: w });
      if (r.nodes) nodes.push(...r.nodes);
    }
  }
  if (!evidence.length) return null;
  // Status codes and headers like "server: cloudflare" only support other evidence.
  if (evidence.every((e) => e.type === 'status')) return null;
  let miss = 1;
  for (const e of evidence) miss *= 1 - e.weight;
  return { evidence, nodes, confidence: 1 - miss };
}

function makeContext(s, raw) {
  const dom = s.mode === 'dom';
  const anyVisible = (nodes, filter) => {
    if (!dom) return null;
    let list = (nodes || []).map((n) => (n && n.node ? n.node : n)).filter(Boolean);
    if (filter) list = list.filter(filter);
    return list.some((n) => s.isVisible(n) === true);
  };
  return {
    dom,
    url: s.url,
    title: s.title,
    text: s.text,
    textLength: s.textLength,
    short: s.textLength <= SHORT_PAGE,
    inline: s.inline,
    status: s.status,
    has: (id) => raw.has(id),
    header: (name) => s.headers[name.toLowerCase()] || '',
    query: (sel) => s.query(sel),
    frames: (re) => {
      const out = s.frames.filter((f) => f.src && re.test(f.src)).map((f) => ({ src: f.src, node: f.node, el: f.el }));
      for (const r of s.resources) if ((r.type === 'iframe' || r.type === 'frame') && re.test(r.url) && !out.some((f) => f.src === r.url)) out.push({ src: r.url, node: null, el: null });
      return out;
    },
    script: (re) => s.scripts.some((u) => re.test(u)) || s.resources.some((r) => SCRIPT_LIKE[r.type] && re.test(r.url)),
    global: (path) => {
      if (!s.win) return false;
      const v = getPath(s.win, path);
      return realGlobal(v) ? v : false;
    },
    anyVisible,
    visibleEl: (el) => (dom && el ? elementVisible(el) === true : null),
  };
}

function buildDetection(id, sig, r, s, ctx, opts) {
  let d = {
    id,
    name: sig.name,
    vendor: sig.vendor || null,
    kind: sig.kind,
    subtype: sig.subtype || null,
    confidence: r.confidence,
    visible: null,
    evidence: r.evidence.slice(),
    site: sig.site || null,
  };
  if (d.kind === 'challenge-page') d.visible = true;
  else if (d.kind === 'protection' || d.kind === 'block-page') d.visible = null;
  else if (s.mode === 'dom') d.visible = r.nodes.some((n) => s.isVisible(n) === true);
  if (sig.refine) {
    try {
      d = sig.refine(d, ctx);
    } catch (_) {
      /* a refine bug must not break detection */
    }
    if (!d) return null;
  }
  if (d.kind === 'protection' || d.kind === 'block-page') d.visible = null;
  d.confidence = Math.round(Math.min(d.confidence, 0.99) * 100) / 100;
  d.evidence = d.evidence.slice(0, 12).map((e) => ({ type: e.type, value: e.value }));
  if (opts.elements && s.mode === 'dom') Object.defineProperty(d, 'elements', { value: r.nodes.map((n) => n.el).filter(Boolean), enumerable: false });
  return d;
}

function finalize(detections, meta) {
  // Catch-all rules give way to a named product.
  const named = detections.some((d) => !d.id.startsWith('generic-') && d.kind !== 'protection');
  let list = named ? detections.filter((d) => !d.id.startsWith('generic-')) : detections;
  const rank = { 'challenge-page': 0, widget: 1, image: 1, question: 1, invisible: 2, 'block-page': 3, protection: 4 };
  list = list.sort((a, b) => (rank[a.kind] - rank[b.kind]) || b.confidence - a.confidence);
  const captchas = list.filter((d) => CAPTCHA_KINDS[d.kind]);
  const visibleKnown = captchas.some((d) => d.visible !== null);
  const result = {
    captcha: captchas.length > 0,
    visible: captchas.some((d) => d.visible === true) ? true : visibleKnown || meta.mode === 'dom' ? false : null,
    challengePage: list.some((d) => d.kind === 'challenge-page'),
    blocked: list.some((d) => d.kind === 'block-page'),
    detections: list,
    summary: '',
    url: meta.url || '',
    mode: meta.mode,
    version: VERSION,
  };
  result.summary = summarize(result);
  return result;
}

function summarize(r) {
  if (!r.detections.length) return 'No captcha found';
  const parts = r.detections.map((d) => {
    let s = d.name + (d.subtype ? ` (${d.subtype})` : '');
    if (d.kind === 'protection') s += ' [bot protection, no captcha shown]';
    else if (d.kind === 'block-page') s += ' [blocked]';
    else if (d.visible === true) s += ' [visible]';
    else if (d.visible === false) s += d.kind === 'invisible' ? ' [invisible]' : ' [not shown]';
    return s;
  });
  return (r.captcha ? 'Captcha found: ' : r.blocked ? 'Blocked: ' : 'No captcha: ') + parts.join(', ');
}

/** Run every signature on a snapshot (from snapshotFromDom or snapshotFromHtml). */
function analyze(s, opts = {}) {
  const min = opts.minConfidence != null ? opts.minConfidence : 0.5;
  const list = getCompiled(opts.signatures);
  const raw = new Map();
  for (const c of list) {
    const r = scoreSignature(c, s);
    if (r && r.confidence >= min) raw.set(c.sig.id, { c, r });
  }
  // Refine twice: the first pass decides which matches survive, the second lets refine() see those survivors
  // (so a weak match that refine() drops does not hide another product).
  let alive = new Set(raw.keys());
  let out = [];
  for (let pass = 0; pass < 2; pass++) {
    const ctx = makeContext(s, alive);
    out = [];
    for (const [id, { c, r }] of raw) {
      const d = buildDetection(id, c.sig, r, s, ctx, opts);
      if (d) out.push(d);
    }
    alive = new Set(out.map((d) => d.id));
  }
  return finalize(out, { url: s.url, mode: s.mode });
}

// ───────────────────────────── Public API ─────────────────────────────

/**
 * Check the current page (browser). Options:
 *   window         the window to check (default: the global window)
 *   deep           search same-origin frames and open shadow roots (default true)
 *   headers/status the response headers and status, if you have them
 *   minConfidence  0..1, default 0.5
 *   elements       true to attach the matched DOM elements (non-enumerable `elements` on each detection)
 */
function detect(opts = {}) {
  return analyze(snapshotFromDom(opts.window, opts), opts);
}

/**
 * Check an HTML string (Node, workers, anywhere). Options: url, headers, status, cookies, minConfidence.
 * Static HTML cannot show widgets that scripts add later, and visibility is unknown (visible: null).
 */
function detectHtml(html, opts = {}) {
  return analyze(snapshotFromHtml(html, opts), opts);
}

// ---------- Responses from HTTP clients and scraper APIs ----------

const LOOKS_HTML = /<(?:!doctype|html|head|body|script|iframe|form|div|title|meta|noscript)\b/i;
const STATUS_KEY = /^(?:status|status_?code|http_?status(?:_?code)?|original_?status|target_?status)$/i;

// A scraper API often wraps the page in JSON ({ "html": "<html>…" }, { "body": … }, { "result": { "content": … } }).
// Find the longest string that looks like HTML, and the status/headers/url next to it.
function unwrapJson(v) {
  let best = null;
  const walk = (o, depth) => {
    if (!o || typeof o !== 'object' || depth > 5) return;
    for (const k of Object.keys(o)) {
      const x = o[k];
      if (typeof x === 'string') {
        if (x.length > 20 && LOOKS_HTML.test(x) && (!best || x.length > best.html.length)) best = { html: x, parent: o };
      } else if (x && typeof x === 'object') walk(x, depth + 1);
    }
  };
  walk(v, 0);
  if (!best) return null;
  const out = { html: best.html };
  for (const k of Object.keys(best.parent)) {
    const x = best.parent[k];
    if (STATUS_KEY.test(k) && Number(x) >= 100 && Number(x) <= 599) out.status = Number(x);
    else if (/^headers$/i.test(k) && x && typeof x === 'object') out.headers = x;
    else if (/^(?:url|final_?url|resolved_?url)$/i.test(k) && typeof x === 'string' && /^https?:/i.test(x)) out.url = x;
  }
  return out;
}

function fromBody(body) {
  let html = body;
  let extra = {};
  if (body && typeof body === 'object' && !(typeof ArrayBuffer !== 'undefined' && body instanceof ArrayBuffer)) {
    extra = unwrapJson(body) || {};
    html = extra.html != null ? extra.html : JSON.stringify(body);
  } else if (typeof body === 'string' && /^\s*[[{]/.test(body)) {
    try {
      const found = unwrapJson(JSON.parse(body));
      if (found) {
        extra = found;
        html = found.html;
      }
    } catch (_) {
      /* not JSON */
    }
  } else if (body != null && typeof body !== 'string') {
    html = typeof TextDecoder !== 'undefined' ? new TextDecoder().decode(body) : String(body);
  }
  return { html: html == null ? '' : String(html), status: extra.status, headers: extra.headers, url: extra.url };
}

/**
 * Check what an HTTP client or a scraper API returned. Accepts a fetch Response, an axios/got-style response
 * ({ data | body, status, headers }), an HTML string, or the parsed JSON a scraper API sent. Always returns a Promise.
 *
 * HTML wrapped in JSON is found on its own, with the status/headers/url next to it. Pass `url` = the page you asked
 * the API to scrape. Options `status` and `headers` override what the response says (most scraper APIs answer 200
 * whatever the site did; that is fine, the page itself is what counts).
 */
async function detectResponse(input, opts = {}) {
  let body = input;
  let status;
  let headers;
  let url;
  if (input && typeof input === 'object' && typeof input.text === 'function' && 'status' in input) {
    // fetch / undici Response (read a clone, so the caller can still read the body)
    const r = typeof input.clone === 'function' && !input.bodyUsed ? input.clone() : input;
    body = await r.text();
    status = input.status;
    headers = input.headers;
    url = input.url;
  } else if (input && typeof input === 'object' && (('data' in input && 'status' in input) || ('body' in input && ('status' in input || 'statusCode' in input)))) {
    // axios ({ data, status, headers }), got / needle / superagent ({ body, statusCode, headers })
    body = 'data' in input ? input.data : input.body;
    status = input.status != null ? input.status : input.statusCode;
    headers = input.headers;
    url = (input.request && (input.request.res && input.request.res.responseUrl)) || input.url;
  }
  const b = fromBody(body);
  // Status and headers found next to the HTML inside the JSON belong to the target site: they win over the API's.
  return detectHtml(b.html, {
    ...opts,
    url: opts.url || b.url || url || '',
    status: opts.status != null ? opts.status : b.status != null ? b.status : status,
    headers: opts.headers || b.headers || headers,
  });
}

/**
 * Combine the result for a page with results from inside its frames (e.g. from Playwright's page.frames()).
 * frames: [{ url, visible, result }] — visible: whether the frame element is shown in the page.
 */
function mergeResults(main, frames = [], opts = {}) {
  const map = new Map();
  for (const d of main.detections) map.set(d.id, { ...d, evidence: d.evidence.slice() });
  const list = getCompiled(opts.signatures);
  for (const f of frames) {
    if (!f || !f.result) continue;
    // A frame that is a known widget's own iframe (e.g. Turnstile's challenges.cloudflare.com frame) belongs to that
    // widget: what runs inside it is the vendor's own code, not another captcha.
    const owner = f.url
      ? list.find((c) => map.has(c.sig.id) && c.m.frames && c.m.frames.some((e) => e.p.test(f.url)))
      : null;
    for (const d0 of f.result.detections) {
      if (d0.kind === 'block-page') continue; // an error page inside a frame is not the page
      if (owner && d0.id !== owner.sig.id) continue;
      if (d0.id === 'generic-challenge' || d0.id === 'generic-block') continue; // wording inside a frame is too weak
      const d = { ...d0, evidence: d0.evidence.map((e) => ({ ...e, frame: f.url || '' })) };
      // A whole-document check inside a frame is a widget on the page.
      if (d.kind === 'challenge-page') {
        d.kind = 'widget';
        d.visible = f.visible != null ? f.visible : true;
      } else if (d.kind !== 'protection' && d.kind !== 'invisible') {
        if (f.visible === false) d.visible = false;
        else if (f.visible === true && d.visible !== true) d.visible = d.visible === false && d.evidence.some((e) => e.type === 'elements' || e.type === 'frames') ? false : true;
      }
      const cur = map.get(d.id);
      if (!cur) {
        d.frame = f.url || '';
        map.set(d.id, d);
        continue;
      }
      cur.confidence = Math.max(cur.confidence, d.confidence);
      if (d.visible === true && cur.kind !== 'invisible') cur.visible = true;
      if (!cur.subtype && d.subtype) cur.subtype = d.subtype;
      if (d.details) cur.details = { ...cur.details, ...d.details };
      for (const e of d.evidence) if (cur.evidence.length < 16 && !cur.evidence.some((x) => x.value === e.value)) cur.evidence.push(e);
    }
  }
  return finalize([...map.values()], { url: main.url, mode: main.mode });
}


return { VERSION, detect, detectHtml, detectResponse, analyze, mergeResults, snapshotFromDom, snapshotFromHtml, signatures: SIGNATURES };
});
