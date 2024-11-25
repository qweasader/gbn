# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856280");
  script_version("2024-07-24T05:06:37+0000");
  script_cve_id("CVE-2023-28858", "CVE-2023-28859");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-07-24 05:06:37 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-05 19:06:46 +0000 (Wed, 05 Apr 2023)");
  script_tag(name:"creation_date", value:"2024-07-10 04:00:36 +0000 (Wed, 10 Jul 2024)");
  script_name("openSUSE: Security Advisory for python (SUSE-SU-2024:1639-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1639-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3KIJTHTGCXAMZDMRXUCA5V6ZEXGXN4KT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the SUSE-SU-2024:1639-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-argcomplete, python-Fabric, python-PyGithub, python-
  antlr4-python3-runtime, python-avro, python-chardet, python-distro, python-
  docker, python-fakeredis, python-fixedint, python-httplib2, python-httpretty,
  python-javaproperties, python-jsondiff, python-knack, python-marshmallow,
  python-opencensus, python-opencensus-context, python-opencensus-ext-threading,
  python-opentelemetry-api, python-opentelemetry-sdk, python-opentelemetry-
  semantic-conventions, python-opentelemetry-test-utils, python-pycomposefile,
  python-pydash, python-redis, python-retrying, python-semver, python-sshtunnel,
  python-strictyaml, python-sure, python-vcrpy, python-xmltodict contains the
  following fixes:

  Changes in python-argcomplete \- Update to 3.3.0 (bsc#1222880): * Preserve
  compatibility with argparse option tuples of length 4. This update is required
  to use argcomplete on Python 3.11.9+ or 3.12.3+. \- update to 3.2.3: * Allow
  register-python-argcomplete output to be used as lazy-loaded zsh completion
  module (#475) \- Move debug_stream initialization to helper method to allow fd 9
  behavior to be overridden in subclasses (#471)

  * update to 3.2.2:

  * Expand tilde in zsh

  * Remove coverage check

  * Fix zsh test failures: avoid coloring terminal

  * update to 3.2.1:

  * Allow explicit zsh global completion activation (#467)

  * Fix and test global completion in zsh (#463, #466)

  * Add yes option to activate-global-python-argcomplete (#461)

  * Test suite improvements

  * drop without_zsh.patch: obsolete

  * update to 3.1.6:

  * Respect user choice in activate-global-python-argcomplete

  * Escape colon in zsh completions. Fixes #456

  * Call _default as a fallback in zsh global completion

  * update to 3.1.4:

  * Call _default as a fallback in zsh global completion

  * zsh: Allow to use external script (#453)

  * Add support for Python 3.12 and drop EOL 3.6 and 3.7 (#449)

  * Use homebrew prefix by default

  * zsh: Allow to use external script (#453)

  Changes in python-Fabric: \- Update to 3.2.2 \- add fix-test-deps.patch to
  remove vendored dependencies *[Bug]: fabric.runners.Remote failed to properly
  deregister its SIGWINCH signal handler on shutdown  in rare situations this
  could cause tracebacks when the Python process receives SIGWINCH while no remote
  session is active. This has been fixed. * [Bug] #2204: The signal handling
  functionality added in Fabric 2.6 caused unrecoverable tracebacks when invoked
  from inside a thread (such as the use of fabric.group.ThreadingGrou ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'python' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"python311-zope.interface-debuginfo", rpm:"python311-zope.interface-debuginfo~6.0~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-yarl-debugsource", rpm:"python-yarl-debugsource~1.9.2~150400.8.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-multidict-debuginfo", rpm:"python311-multidict-debuginfo~6.0.4~150400.7.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-multidict-debugsource", rpm:"python-multidict-debugsource~6.0.4~150400.7.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-psutil", rpm:"python311-psutil~5.9.5~150400.6.9.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiohttp-debuginfo", rpm:"python311-aiohttp-debuginfo~3.9.3~150400.10.18.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-zope.interface", rpm:"python311-zope.interface~6.0~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wrapt-debuginfo", rpm:"python311-wrapt-debuginfo~1.15.0~150400.12.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-zope.interface-debugsource", rpm:"python-zope.interface-debugsource~6.0~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-frozenlist-debuginfo", rpm:"python311-frozenlist-debuginfo~1.3.3~150400.9.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-multidict", rpm:"python311-multidict~6.0.4~150400.7.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-frozenlist-debugsource", rpm:"python-frozenlist-debugsource~1.3.3~150400.9.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wrapt", rpm:"python311-wrapt~1.15.0~150400.12.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-frozenlist", rpm:"python311-frozenlist~1.3.3~150400.9.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-psutil-debuginfo", rpm:"python311-psutil-debuginfo~5.9.5~150400.6.9.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-wrapt-debugsource", rpm:"python-wrapt-debugsource~1.15.0~150400.12.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-yarl", rpm:"python311-yarl~1.9.2~150400.8.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiohttp", rpm:"python311-aiohttp~3.9.3~150400.10.18.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-yarl-debuginfo", rpm:"python311-yarl-debuginfo~1.9.2~150400.8.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-psutil-debugsource", rpm:"python-psutil-debugsource~5.9.5~150400.6.9.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-aiohttp-debugsource", rpm:"python-aiohttp-debugsource~3.9.3~150400.10.18.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiosignal", rpm:"python311-aiosignal~1.3.1~150400.9.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-PyGithub", rpm:"python311-PyGithub~1.57~150400.10.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus-ext-threading", rpm:"python311-opencensus-ext-threading~0.1.2~150400.10.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-websocket-client", rpm:"python311-websocket-client~1.5.1~150400.13.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-marshmallow", rpm:"python311-marshmallow~3.20.2~150400.9.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-avro", rpm:"python311-avro~1.11.3~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-portalocker", rpm:"python311-portalocker~2.7.0~150400.10.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Automat", rpm:"python311-Automat~22.10.0~150400.3.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fluidity-sm", rpm:"python311-fluidity-sm~0.2.0~150400.10.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-distro", rpm:"python311-distro~1.9.0~150400.12.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-conch_nacl", rpm:"python311-Twisted-conch_nacl~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Pygments", rpm:"python311-Pygments~2.15.1~150400.7.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-blinker", rpm:"python311-blinker~1.6.2~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-constantly", rpm:"python311-constantly~15.1.0~150400.12.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-zipp", rpm:"python311-zipp~3.15.0~150400.10.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-chardet", rpm:"python311-chardet~5.2.0~150400.13.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-httplib2", rpm:"python311-httplib2~0.22.0~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-strictyaml", rpm:"python311-strictyaml~1.7.3~150400.9.3.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-retrying", rpm:"python311-retrying~1.3.4~150400.12.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-semver", rpm:"python311-semver~3.0.2~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus", rpm:"python311-opencensus~0.11.4~150400.10.6.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-vcrpy", rpm:"python311-vcrpy~6.0.1~150400.7.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-http2", rpm:"python311-Twisted-http2~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Fabric", rpm:"python311-Fabric~3.2.2~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-docker", rpm:"python311-docker~7.0.0~150400.8.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tabulate", rpm:"python311-tabulate~0.9.0~150400.11.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-asgiref", rpm:"python311-asgiref~3.6.0~150400.9.7.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-contextvars", rpm:"python311-Twisted-contextvars~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-sortedcontainers", rpm:"python311-sortedcontainers~2.4.0~150400.8.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pydash", rpm:"python311-pydash~6.0.2~150400.9.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-async_timeout", rpm:"python311-async_timeout~4.0.2~150400.10.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-lexicon", rpm:"python311-lexicon~2.0.1~150400.10.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-PyJWT", rpm:"python311-PyJWT~2.8.0~150400.8.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-httpretty", rpm:"python311-httpretty~1.1.4~150400.11.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-paramiko-doc", rpm:"python-paramiko-doc~3.4.0~150400.13.10.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-semantic-conventions", rpm:"python311-opentelemetry-semantic-conventions~0.44b0~150400.9.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pycomposefile", rpm:"python311-pycomposefile~0.0.30~150400.9.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-service_identity", rpm:"python311-service_identity~23.1.0~150400.8.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-isodate", rpm:"python311-isodate~0.6.1~150400.12.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-humanfriendly", rpm:"python311-humanfriendly~10.0~150400.13.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-all_non_platform", rpm:"python311-Twisted-all_non_platform~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-requests-oauthlib", rpm:"python311-requests-oauthlib~1.3.1~150400.12.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-redis", rpm:"python311-redis~5.0.1~150400.12.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-sshtunnel", rpm:"python311-sshtunnel~0.4.0~150400.5.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wheel", rpm:"python311-wheel~0.40.0~150400.13.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-conch", rpm:"python311-Twisted-conch~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-jsondiff", rpm:"python311-jsondiff~2.0.0~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-typing_extensions", rpm:"python311-typing_extensions~4.5.0~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-knack", rpm:"python311-knack~0.11.0~150400.10.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-tls", rpm:"python311-Twisted-tls~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-oauthlib", rpm:"python311-oauthlib~3.2.2~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus-context", rpm:"python311-opencensus-context~0.1.3~150400.10.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-paramiko", rpm:"python311-paramiko~3.4.0~150400.13.10.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-serial", rpm:"python311-Twisted-serial~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tqdm", rpm:"python311-tqdm~4.66.1~150400.9.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Deprecated", rpm:"python311-Deprecated~1.2.14~150400.10.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-javaproperties", rpm:"python311-javaproperties~0.8.1~150400.10.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fixedint", rpm:"python311-fixedint~0.2.0~150400.9.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-scp", rpm:"python311-scp~0.14.5~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-invoke", rpm:"python311-invoke~2.1.2~150400.10.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fakeredis", rpm:"python311-fakeredis~2.21.0~150400.9.3.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-antlr4-python3-runtime", rpm:"python311-antlr4-python3-runtime~4.13.1~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-decorator", rpm:"python311-decorator~5.1.1~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-argcomplete", rpm:"python311-argcomplete~3.3.0~150400.12.12.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-incremental", rpm:"python311-incremental~22.10.0~150400.3.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-test-utils", rpm:"python311-opentelemetry-test-utils~0.44b0~150400.9.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pathspec", rpm:"python311-pathspec~0.11.1~150400.9.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pkginfo", rpm:"python311-pkginfo~1.9.6~150400.7.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-sdk", rpm:"python311-opentelemetry-sdk~1.23.0~150400.9.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pip", rpm:"python311-pip~22.3.1~150400.17.16.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-importlib-metadata", rpm:"python311-importlib-metadata~6.8.0~150400.10.9.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pyparsing", rpm:"python311-pyparsing~3.0.9~150400.5.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-hyperlink", rpm:"python311-hyperlink~21.0.0~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted", rpm:"python311-Twisted~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tqdm-bash-completion", rpm:"python-tqdm-bash-completion~4.66.1~150400.9.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-api", rpm:"python311-opentelemetry-api~1.23.0~150400.10.7.1##", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-zope.interface-debuginfo", rpm:"python311-zope.interface-debuginfo~6.0~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-yarl-debugsource", rpm:"python-yarl-debugsource~1.9.2~150400.8.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-multidict-debuginfo", rpm:"python311-multidict-debuginfo~6.0.4~150400.7.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-multidict-debugsource", rpm:"python-multidict-debugsource~6.0.4~150400.7.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-psutil", rpm:"python311-psutil~5.9.5~150400.6.9.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiohttp-debuginfo", rpm:"python311-aiohttp-debuginfo~3.9.3~150400.10.18.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-zope.interface", rpm:"python311-zope.interface~6.0~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wrapt-debuginfo", rpm:"python311-wrapt-debuginfo~1.15.0~150400.12.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-zope.interface-debugsource", rpm:"python-zope.interface-debugsource~6.0~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-frozenlist-debuginfo", rpm:"python311-frozenlist-debuginfo~1.3.3~150400.9.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-multidict", rpm:"python311-multidict~6.0.4~150400.7.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-frozenlist-debugsource", rpm:"python-frozenlist-debugsource~1.3.3~150400.9.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wrapt", rpm:"python311-wrapt~1.15.0~150400.12.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-frozenlist", rpm:"python311-frozenlist~1.3.3~150400.9.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-psutil-debuginfo", rpm:"python311-psutil-debuginfo~5.9.5~150400.6.9.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-wrapt-debugsource", rpm:"python-wrapt-debugsource~1.15.0~150400.12.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-yarl", rpm:"python311-yarl~1.9.2~150400.8.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiohttp", rpm:"python311-aiohttp~3.9.3~150400.10.18.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-yarl-debuginfo", rpm:"python311-yarl-debuginfo~1.9.2~150400.8.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-psutil-debugsource", rpm:"python-psutil-debugsource~5.9.5~150400.6.9.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-aiohttp-debugsource", rpm:"python-aiohttp-debugsource~3.9.3~150400.10.18.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiosignal", rpm:"python311-aiosignal~1.3.1~150400.9.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-PyGithub", rpm:"python311-PyGithub~1.57~150400.10.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus-ext-threading", rpm:"python311-opencensus-ext-threading~0.1.2~150400.10.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-websocket-client", rpm:"python311-websocket-client~1.5.1~150400.13.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-marshmallow", rpm:"python311-marshmallow~3.20.2~150400.9.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-avro", rpm:"python311-avro~1.11.3~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-portalocker", rpm:"python311-portalocker~2.7.0~150400.10.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Automat", rpm:"python311-Automat~22.10.0~150400.3.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fluidity-sm", rpm:"python311-fluidity-sm~0.2.0~150400.10.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-distro", rpm:"python311-distro~1.9.0~150400.12.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-conch_nacl", rpm:"python311-Twisted-conch_nacl~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Pygments", rpm:"python311-Pygments~2.15.1~150400.7.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-blinker", rpm:"python311-blinker~1.6.2~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-constantly", rpm:"python311-constantly~15.1.0~150400.12.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-zipp", rpm:"python311-zipp~3.15.0~150400.10.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-chardet", rpm:"python311-chardet~5.2.0~150400.13.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-httplib2", rpm:"python311-httplib2~0.22.0~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-strictyaml", rpm:"python311-strictyaml~1.7.3~150400.9.3.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-retrying", rpm:"python311-retrying~1.3.4~150400.12.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-semver", rpm:"python311-semver~3.0.2~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus", rpm:"python311-opencensus~0.11.4~150400.10.6.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-vcrpy", rpm:"python311-vcrpy~6.0.1~150400.7.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-http2", rpm:"python311-Twisted-http2~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Fabric", rpm:"python311-Fabric~3.2.2~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-docker", rpm:"python311-docker~7.0.0~150400.8.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tabulate", rpm:"python311-tabulate~0.9.0~150400.11.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-asgiref", rpm:"python311-asgiref~3.6.0~150400.9.7.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-contextvars", rpm:"python311-Twisted-contextvars~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-sortedcontainers", rpm:"python311-sortedcontainers~2.4.0~150400.8.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pydash", rpm:"python311-pydash~6.0.2~150400.9.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-async_timeout", rpm:"python311-async_timeout~4.0.2~150400.10.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-lexicon", rpm:"python311-lexicon~2.0.1~150400.10.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-PyJWT", rpm:"python311-PyJWT~2.8.0~150400.8.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-httpretty", rpm:"python311-httpretty~1.1.4~150400.11.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-paramiko-doc", rpm:"python-paramiko-doc~3.4.0~150400.13.10.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-semantic-conventions", rpm:"python311-opentelemetry-semantic-conventions~0.44b0~150400.9.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pycomposefile", rpm:"python311-pycomposefile~0.0.30~150400.9.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-service_identity", rpm:"python311-service_identity~23.1.0~150400.8.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-isodate", rpm:"python311-isodate~0.6.1~150400.12.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-humanfriendly", rpm:"python311-humanfriendly~10.0~150400.13.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-all_non_platform", rpm:"python311-Twisted-all_non_platform~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-requests-oauthlib", rpm:"python311-requests-oauthlib~1.3.1~150400.12.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-redis", rpm:"python311-redis~5.0.1~150400.12.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-sshtunnel", rpm:"python311-sshtunnel~0.4.0~150400.5.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wheel", rpm:"python311-wheel~0.40.0~150400.13.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-conch", rpm:"python311-Twisted-conch~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-jsondiff", rpm:"python311-jsondiff~2.0.0~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-typing_extensions", rpm:"python311-typing_extensions~4.5.0~150400.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-knack", rpm:"python311-knack~0.11.0~150400.10.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-tls", rpm:"python311-Twisted-tls~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-oauthlib", rpm:"python311-oauthlib~3.2.2~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus-context", rpm:"python311-opencensus-context~0.1.3~150400.10.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-paramiko", rpm:"python311-paramiko~3.4.0~150400.13.10.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-serial", rpm:"python311-Twisted-serial~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tqdm", rpm:"python311-tqdm~4.66.1~150400.9.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Deprecated", rpm:"python311-Deprecated~1.2.14~150400.10.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-javaproperties", rpm:"python311-javaproperties~0.8.1~150400.10.4.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fixedint", rpm:"python311-fixedint~0.2.0~150400.9.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-scp", rpm:"python311-scp~0.14.5~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-invoke", rpm:"python311-invoke~2.1.2~150400.10.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fakeredis", rpm:"python311-fakeredis~2.21.0~150400.9.3.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-antlr4-python3-runtime", rpm:"python311-antlr4-python3-runtime~4.13.1~150400.10.4.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-decorator", rpm:"python311-decorator~5.1.1~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-argcomplete", rpm:"python311-argcomplete~3.3.0~150400.12.12.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-incremental", rpm:"python311-incremental~22.10.0~150400.3.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-test-utils", rpm:"python311-opentelemetry-test-utils~0.44b0~150400.9.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pathspec", rpm:"python311-pathspec~0.11.1~150400.9.7.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pkginfo", rpm:"python311-pkginfo~1.9.6~150400.7.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-sdk", rpm:"python311-opentelemetry-sdk~1.23.0~150400.9.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pip", rpm:"python311-pip~22.3.1~150400.17.16.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-importlib-metadata", rpm:"python311-importlib-metadata~6.8.0~150400.10.9.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pyparsing", rpm:"python311-pyparsing~3.0.9~150400.5.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-hyperlink", rpm:"python311-hyperlink~21.0.0~150400.12.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted", rpm:"python311-Twisted~22.10.0~150400.5.17.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tqdm-bash-completion", rpm:"python-tqdm-bash-completion~4.66.1~150400.9.7.4", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-api", rpm:"python311-opentelemetry-api~1.23.0~150400.10.7.1##", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"python311-zope.interface-debuginfo", rpm:"python311-zope.interface-debuginfo~6.0~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-yarl-debugsource", rpm:"python-yarl-debugsource~1.9.2~150400.8.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-multidict-debuginfo", rpm:"python311-multidict-debuginfo~6.0.4~150400.7.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-multidict-debugsource", rpm:"python-multidict-debugsource~6.0.4~150400.7.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-psutil", rpm:"python311-psutil~5.9.5~150400.6.9.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiohttp-debuginfo", rpm:"python311-aiohttp-debuginfo~3.9.3~150400.10.18.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-zope.interface", rpm:"python311-zope.interface~6.0~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wrapt-debuginfo", rpm:"python311-wrapt-debuginfo~1.15.0~150400.12.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-zope.interface-debugsource", rpm:"python-zope.interface-debugsource~6.0~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-frozenlist-debuginfo", rpm:"python311-frozenlist-debuginfo~1.3.3~150400.9.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-multidict", rpm:"python311-multidict~6.0.4~150400.7.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-frozenlist-debugsource", rpm:"python-frozenlist-debugsource~1.3.3~150400.9.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wrapt", rpm:"python311-wrapt~1.15.0~150400.12.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-frozenlist", rpm:"python311-frozenlist~1.3.3~150400.9.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-psutil-debuginfo", rpm:"python311-psutil-debuginfo~5.9.5~150400.6.9.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-wrapt-debugsource", rpm:"python-wrapt-debugsource~1.15.0~150400.12.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-yarl", rpm:"python311-yarl~1.9.2~150400.8.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiohttp", rpm:"python311-aiohttp~3.9.3~150400.10.18.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-yarl-debuginfo", rpm:"python311-yarl-debuginfo~1.9.2~150400.8.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-psutil-debugsource", rpm:"python-psutil-debugsource~5.9.5~150400.6.9.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-aiohttp-debugsource", rpm:"python-aiohttp-debugsource~3.9.3~150400.10.18.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiosignal", rpm:"python311-aiosignal~1.3.1~150400.9.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-PyGithub", rpm:"python311-PyGithub~1.57~150400.10.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus-ext-threading", rpm:"python311-opencensus-ext-threading~0.1.2~150400.10.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-websocket-client", rpm:"python311-websocket-client~1.5.1~150400.13.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-marshmallow", rpm:"python311-marshmallow~3.20.2~150400.9.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-avro", rpm:"python311-avro~1.11.3~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-portalocker", rpm:"python311-portalocker~2.7.0~150400.10.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Automat", rpm:"python311-Automat~22.10.0~150400.3.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fluidity-sm", rpm:"python311-fluidity-sm~0.2.0~150400.10.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-distro", rpm:"python311-distro~1.9.0~150400.12.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-conch_nacl", rpm:"python311-Twisted-conch_nacl~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Pygments", rpm:"python311-Pygments~2.15.1~150400.7.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-blinker", rpm:"python311-blinker~1.6.2~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-constantly", rpm:"python311-constantly~15.1.0~150400.12.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-zipp", rpm:"python311-zipp~3.15.0~150400.10.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-chardet", rpm:"python311-chardet~5.2.0~150400.13.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-httplib2", rpm:"python311-httplib2~0.22.0~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-strictyaml", rpm:"python311-strictyaml~1.7.3~150400.9.3.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-retrying", rpm:"python311-retrying~1.3.4~150400.12.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-semver", rpm:"python311-semver~3.0.2~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus", rpm:"python311-opencensus~0.11.4~150400.10.6.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-vcrpy", rpm:"python311-vcrpy~6.0.1~150400.7.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-http2", rpm:"python311-Twisted-http2~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Fabric", rpm:"python311-Fabric~3.2.2~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-docker", rpm:"python311-docker~7.0.0~150400.8.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tabulate", rpm:"python311-tabulate~0.9.0~150400.11.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-asgiref", rpm:"python311-asgiref~3.6.0~150400.9.7.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-contextvars", rpm:"python311-Twisted-contextvars~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-sortedcontainers", rpm:"python311-sortedcontainers~2.4.0~150400.8.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pydash", rpm:"python311-pydash~6.0.2~150400.9.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-async_timeout", rpm:"python311-async_timeout~4.0.2~150400.10.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-lexicon", rpm:"python311-lexicon~2.0.1~150400.10.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-PyJWT", rpm:"python311-PyJWT~2.8.0~150400.8.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-httpretty", rpm:"python311-httpretty~1.1.4~150400.11.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-paramiko-doc", rpm:"python-paramiko-doc~3.4.0~150400.13.10.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-semantic-conventions", rpm:"python311-opentelemetry-semantic-conventions~0.44b0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pycomposefile", rpm:"python311-pycomposefile~0.0.30~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-service_identity", rpm:"python311-service_identity~23.1.0~150400.8.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-isodate", rpm:"python311-isodate~0.6.1~150400.12.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-humanfriendly", rpm:"python311-humanfriendly~10.0~150400.13.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-all_non_platform", rpm:"python311-Twisted-all_non_platform~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-requests-oauthlib", rpm:"python311-requests-oauthlib~1.3.1~150400.12.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-redis", rpm:"python311-redis~5.0.1~150400.12.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-sshtunnel", rpm:"python311-sshtunnel~0.4.0~150400.5.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wheel", rpm:"python311-wheel~0.40.0~150400.13.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-conch", rpm:"python311-Twisted-conch~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-jsondiff", rpm:"python311-jsondiff~2.0.0~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-typing_extensions", rpm:"python311-typing_extensions~4.5.0~150400.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-knack", rpm:"python311-knack~0.11.0~150400.10.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-tls", rpm:"python311-Twisted-tls~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-oauthlib", rpm:"python311-oauthlib~3.2.2~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus-context", rpm:"python311-opencensus-context~0.1.3~150400.10.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-paramiko", rpm:"python311-paramiko~3.4.0~150400.13.10.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-serial", rpm:"python311-Twisted-serial~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tqdm", rpm:"python311-tqdm~4.66.1~150400.9.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Deprecated", rpm:"python311-Deprecated~1.2.14~150400.10.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-javaproperties", rpm:"python311-javaproperties~0.8.1~150400.10.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fixedint", rpm:"python311-fixedint~0.2.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-scp", rpm:"python311-scp~0.14.5~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-xmltodict", rpm:"python311-xmltodict~0.13.0~150400.12.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-invoke", rpm:"python311-invoke~2.1.2~150400.10.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fakeredis", rpm:"python311-fakeredis~2.21.0~150400.9.3.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-antlr4-python3-runtime", rpm:"python311-antlr4-python3-runtime~4.13.1~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-decorator", rpm:"python311-decorator~5.1.1~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-argcomplete", rpm:"python311-argcomplete~3.3.0~150400.12.12.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-incremental", rpm:"python311-incremental~22.10.0~150400.3.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-test-utils", rpm:"python311-opentelemetry-test-utils~0.44b0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pathspec", rpm:"python311-pathspec~0.11.1~150400.9.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pkginfo", rpm:"python311-pkginfo~1.9.6~150400.7.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-sdk", rpm:"python311-opentelemetry-sdk~1.23.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pip", rpm:"python311-pip~22.3.1~150400.17.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-importlib-metadata", rpm:"python311-importlib-metadata~6.8.0~150400.10.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pyparsing", rpm:"python311-pyparsing~3.0.9~150400.5.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-sure", rpm:"python311-sure~2.0.1~150400.12.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-hyperlink", rpm:"python311-hyperlink~21.0.0~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted", rpm:"python311-Twisted~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tqdm-bash-completion", rpm:"python-tqdm-bash-completion~4.66.1~150400.9.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-api", rpm:"python311-opentelemetry-api~1.23.0~150400.10.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-zope.interface-debuginfo", rpm:"python311-zope.interface-debuginfo~6.0~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-yarl-debugsource", rpm:"python-yarl-debugsource~1.9.2~150400.8.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-multidict-debuginfo", rpm:"python311-multidict-debuginfo~6.0.4~150400.7.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-multidict-debugsource", rpm:"python-multidict-debugsource~6.0.4~150400.7.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-psutil", rpm:"python311-psutil~5.9.5~150400.6.9.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiohttp-debuginfo", rpm:"python311-aiohttp-debuginfo~3.9.3~150400.10.18.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-zope.interface", rpm:"python311-zope.interface~6.0~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wrapt-debuginfo", rpm:"python311-wrapt-debuginfo~1.15.0~150400.12.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-zope.interface-debugsource", rpm:"python-zope.interface-debugsource~6.0~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-frozenlist-debuginfo", rpm:"python311-frozenlist-debuginfo~1.3.3~150400.9.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-multidict", rpm:"python311-multidict~6.0.4~150400.7.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-frozenlist-debugsource", rpm:"python-frozenlist-debugsource~1.3.3~150400.9.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wrapt", rpm:"python311-wrapt~1.15.0~150400.12.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-frozenlist", rpm:"python311-frozenlist~1.3.3~150400.9.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-psutil-debuginfo", rpm:"python311-psutil-debuginfo~5.9.5~150400.6.9.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-wrapt-debugsource", rpm:"python-wrapt-debugsource~1.15.0~150400.12.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-yarl", rpm:"python311-yarl~1.9.2~150400.8.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiohttp", rpm:"python311-aiohttp~3.9.3~150400.10.18.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-yarl-debuginfo", rpm:"python311-yarl-debuginfo~1.9.2~150400.8.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-psutil-debugsource", rpm:"python-psutil-debugsource~5.9.5~150400.6.9.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-aiohttp-debugsource", rpm:"python-aiohttp-debugsource~3.9.3~150400.10.18.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-aiosignal", rpm:"python311-aiosignal~1.3.1~150400.9.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-PyGithub", rpm:"python311-PyGithub~1.57~150400.10.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus-ext-threading", rpm:"python311-opencensus-ext-threading~0.1.2~150400.10.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-websocket-client", rpm:"python311-websocket-client~1.5.1~150400.13.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-marshmallow", rpm:"python311-marshmallow~3.20.2~150400.9.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-avro", rpm:"python311-avro~1.11.3~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-portalocker", rpm:"python311-portalocker~2.7.0~150400.10.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Automat", rpm:"python311-Automat~22.10.0~150400.3.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fluidity-sm", rpm:"python311-fluidity-sm~0.2.0~150400.10.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-distro", rpm:"python311-distro~1.9.0~150400.12.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-conch_nacl", rpm:"python311-Twisted-conch_nacl~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Pygments", rpm:"python311-Pygments~2.15.1~150400.7.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-blinker", rpm:"python311-blinker~1.6.2~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-constantly", rpm:"python311-constantly~15.1.0~150400.12.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-zipp", rpm:"python311-zipp~3.15.0~150400.10.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-chardet", rpm:"python311-chardet~5.2.0~150400.13.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-httplib2", rpm:"python311-httplib2~0.22.0~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-strictyaml", rpm:"python311-strictyaml~1.7.3~150400.9.3.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-retrying", rpm:"python311-retrying~1.3.4~150400.12.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-semver", rpm:"python311-semver~3.0.2~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus", rpm:"python311-opencensus~0.11.4~150400.10.6.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-vcrpy", rpm:"python311-vcrpy~6.0.1~150400.7.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-http2", rpm:"python311-Twisted-http2~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Fabric", rpm:"python311-Fabric~3.2.2~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-docker", rpm:"python311-docker~7.0.0~150400.8.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tabulate", rpm:"python311-tabulate~0.9.0~150400.11.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-asgiref", rpm:"python311-asgiref~3.6.0~150400.9.7.3", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-contextvars", rpm:"python311-Twisted-contextvars~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-sortedcontainers", rpm:"python311-sortedcontainers~2.4.0~150400.8.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pydash", rpm:"python311-pydash~6.0.2~150400.9.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-async_timeout", rpm:"python311-async_timeout~4.0.2~150400.10.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-lexicon", rpm:"python311-lexicon~2.0.1~150400.10.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-PyJWT", rpm:"python311-PyJWT~2.8.0~150400.8.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-httpretty", rpm:"python311-httpretty~1.1.4~150400.11.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-paramiko-doc", rpm:"python-paramiko-doc~3.4.0~150400.13.10.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-semantic-conventions", rpm:"python311-opentelemetry-semantic-conventions~0.44b0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pycomposefile", rpm:"python311-pycomposefile~0.0.30~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-service_identity", rpm:"python311-service_identity~23.1.0~150400.8.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-isodate", rpm:"python311-isodate~0.6.1~150400.12.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-humanfriendly", rpm:"python311-humanfriendly~10.0~150400.13.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-all_non_platform", rpm:"python311-Twisted-all_non_platform~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-requests-oauthlib", rpm:"python311-requests-oauthlib~1.3.1~150400.12.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-redis", rpm:"python311-redis~5.0.1~150400.12.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-sshtunnel", rpm:"python311-sshtunnel~0.4.0~150400.5.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-wheel", rpm:"python311-wheel~0.40.0~150400.13.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-conch", rpm:"python311-Twisted-conch~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-jsondiff", rpm:"python311-jsondiff~2.0.0~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-typing_extensions", rpm:"python311-typing_extensions~4.5.0~150400.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-knack", rpm:"python311-knack~0.11.0~150400.10.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-tls", rpm:"python311-Twisted-tls~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-oauthlib", rpm:"python311-oauthlib~3.2.2~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opencensus-context", rpm:"python311-opencensus-context~0.1.3~150400.10.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-paramiko", rpm:"python311-paramiko~3.4.0~150400.13.10.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted-serial", rpm:"python311-Twisted-serial~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tqdm", rpm:"python311-tqdm~4.66.1~150400.9.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Deprecated", rpm:"python311-Deprecated~1.2.14~150400.10.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-javaproperties", rpm:"python311-javaproperties~0.8.1~150400.10.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fixedint", rpm:"python311-fixedint~0.2.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-scp", rpm:"python311-scp~0.14.5~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-xmltodict", rpm:"python311-xmltodict~0.13.0~150400.12.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-invoke", rpm:"python311-invoke~2.1.2~150400.10.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-fakeredis", rpm:"python311-fakeredis~2.21.0~150400.9.3.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-antlr4-python3-runtime", rpm:"python311-antlr4-python3-runtime~4.13.1~150400.10.4.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-decorator", rpm:"python311-decorator~5.1.1~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-argcomplete", rpm:"python311-argcomplete~3.3.0~150400.12.12.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-incremental", rpm:"python311-incremental~22.10.0~150400.3.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-test-utils", rpm:"python311-opentelemetry-test-utils~0.44b0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pathspec", rpm:"python311-pathspec~0.11.1~150400.9.7.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pkginfo", rpm:"python311-pkginfo~1.9.6~150400.7.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-sdk", rpm:"python311-opentelemetry-sdk~1.23.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pip", rpm:"python311-pip~22.3.1~150400.17.16.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-importlib-metadata", rpm:"python311-importlib-metadata~6.8.0~150400.10.9.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-pyparsing", rpm:"python311-pyparsing~3.0.9~150400.5.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-sure", rpm:"python311-sure~2.0.1~150400.12.4.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-hyperlink", rpm:"python311-hyperlink~21.0.0~150400.12.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-Twisted", rpm:"python311-Twisted~22.10.0~150400.5.17.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tqdm-bash-completion", rpm:"python-tqdm-bash-completion~4.66.1~150400.9.7.4", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-opentelemetry-api", rpm:"python311-opentelemetry-api~1.23.0~150400.10.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);