---
title: Regions and presets
description: What nw doctor checks, how region presets work, and what each reference target is for.
weight: 8
---

`nw doctor` tells you whether a problem is **local**, **domestic** or **international**. To do that it needs reference points: a few resolvers and a few large, stable services. A **region preset** is that list, reviewed and shipped inside the program.

```sh
nw doctor                  # the global preset
nw doctor --region ir      # global, plus domestic anchors
```

## What nw doctor does

1. **Local checks.** Is a network interface up with an address that can reach beyond this machine? Does the operating system have a default route? Are DNS servers configured? Is a proxy set? None of this sends a packet; the route check asks the operating system which route it would use.
2. **Name resolution.** The system resolver looks up each reference host. Each resolver you compare (see below) looks up the first two hosts of each scope, so the system resolver is set against others, and differences are reported as observations.
3. **Reachability.** Each reference target gets one HTTPS request. If the system resolver could not resolve a host but another resolver could, nw uses that answer to connect, so a failing resolver is not mistaken for a network outage.
4. **A verdict**, from the findings and the reachability of each scope.

Everything it contacts is listed on this page and in [Privacy](../privacy/).

## The verdict

| Verdict | Means |
|---|---|
| `healthy` | Every reference target that was checked is reachable |
| `local` | The problem is on this machine or in its configuration: no usable interface, no default route, no DNS server configured, or the system resolver failing for every name |
| `domestic` | Domestic targets are unreachable while international ones answer |
| `international` | International targets are unreachable while the local checks and the domestic targets pass |
| `upstream` | The local checks pass but nothing beyond this machine answers (or, without domestic anchors, the international targets do not answer) |
| `partial` | Some reference targets answer and some do not |

Each scope (`local`, `domestic`, `international`) also has its own status: `ok` or `problem` for local; `reachable`, `partial`, `unreachable` or `not checked` for the others. A scope is judged from several targets, so one target being down is a warning, not an outage.

A verdict is a statement about this network at this moment. The report's hypotheses say what else could explain it and what was not checked. For example, `international` does not say where the traffic stops or why.

## Choosing a region

A preset is used only when you choose it. nw never detects your country. Choose it with `--region`, the `NW_REGION` environment variable, or `region` in the [config file](../commands/#nw-config). The default for `nw doctor` is `global`.

| Preset | Contains |
|---|---|
| `global` | Public resolvers and large HTTPS endpoints, for international reachability |
| `ir` | Everything in `global`, plus domestic anchors, so a report can say that domestic reachability works while international does not |
| `ru` | Everything in `global`, plus domestic anchors for Russia |
| `tr` | Everything in `global`, plus domestic anchors for Turkey |
| `cn` | Everything in `global`, plus domestic anchors for mainland China |

New regions are added through pull requests that explain, for each target, why it was chosen. The proposal template is "Region preset proposal".

## Resolvers

The system resolver is always measured as the baseline. Other resolvers are compared with it, and the list comes from the first source that sets one:

1. the `--resolver` flags
2. the `NW_RESOLVERS` environment variable (comma-separated)
3. `resolvers` in the config file
4. the resolvers of the region preset, **only when you chose the region** (so nothing contacts a public resolver unasked)

For `nw doctor`, when none of those apply, the preset's resolvers are used, because comparing against reference resolvers is what the command is for. A compared resolver that fails is a warning when you chose it and informational when it came from the preset.

The `ir`, `ru`, `tr` and `cn` presets ship **no domestic resolver**: none could be verified as both stable and neutral. Add the ones you trust:

```toml
# config file
resolvers = ["192.0.2.53", "tcp://198.51.100.53"]
```

## The reference targets

Every entry records why it was chosen. Targets are stable, neutral and unrelated to any circumvention service.

### global

Resolvers:

| Resolver | Why |
|---|---|
| `1.1.1.1` Cloudflare | Anycast public resolver run by a large network operator; stable address, widely deployed |
| `8.8.8.8` Google Public DNS | Anycast public resolver run by a large operator; stable address, widely deployed |
| `9.9.9.9` Quad9 | Anycast public resolver run by a non-profit operator; stable address, independent of the other two |

Targets (international):

| Target | Why |
|---|---|
| `cp.cloudflare.com` | A check endpoint published for connectivity detection; returns an empty 204 response, so it is light and stable |
| `www.google.com` | A widely used connectivity check endpoint that returns an empty 204 response; operated independently of the Cloudflare one |
| `www.wikipedia.org` | A large, stable, non-commercial site served from several regions; a third operator independent of the two above |

### ir (in addition)

Targets (domestic):

| Target | Why |
|---|---|
| `www.digikala.com` | One of the largest domestic e-commerce sites; long-lived, heavily used, operated independently of the other anchors |
| `www.aparat.com` | A large domestic video platform; a different sector and operator from the other anchors |
| `divar.ir` | A large domestic classifieds service; a different sector and operator from the other anchors |

The anchors are ordinary commercial services of different operators and sectors. Several are used so that one site's outage does not decide the verdict. Reviewers inside the region are asked to check them before each release.

### ru (in addition)

Targets (domestic):

| Target | Why |
|---|---|
| `ya.ru` | A large domestic search and services portal; long-lived and heavily used |
| `vk.com` | A large domestic social network; a different sector and operator from the other anchors |
| `www.gosuslugi.ru` | The national public services portal; a different sector and operator from the other anchors |

### tr (in addition)

Targets (domestic):

| Target | Why |
|---|---|
| `www.turkiye.gov.tr` | The national public services portal; long-lived and heavily used |
| `www.hurriyet.com.tr` | A large domestic news site; a different sector and operator from the other anchors |
| `www.garantibbva.com.tr` | A large domestic bank; a different sector and operator from the other anchors |

### cn (in addition)

Targets (domestic):

| Target | Why |
|---|---|
| `www.baidu.com` | A large domestic search engine; long-lived and heavily used |
| `www.jd.com` | A large domestic e-commerce site; a different sector and operator from the other anchors |
| `www.taobao.com` | A large domestic e-commerce marketplace; operated independently of the other anchors |

The `ru`, `tr` and `cn` anchors were checked for a response from outside their regions only. Some of them do not answer from outside. Reviewers inside each region are asked to check them before each release.

## Limits

nw doctor measures from where you run it. It uses a handful of reference points, not the whole internet, and it does not trace where along the path traffic stops. For one destination, use [`nw diagnose`](../diagnostics/).
