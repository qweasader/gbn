# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0068.1");
  script_cve_id("CVE-2020-1971", "CVE-2020-8265", "CVE-2020-8287");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:46 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-14 20:04:54 +0000 (Thu, 14 Jan 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0068-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0068-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210068-1/");
  script_xref(name:"URL", value:"https://cwe.mitre.org/data/definitions/444.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs12' package(s) announced via the SUSE-SU-2021:0068-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs12 fixes the following issues:

New upstream LTS version 12.20.1:
 * CVE-2020-8265: use-after-free in TLSWrap (High) bug in TLS
 implementation. When writing to a TLS enabled socket,
 node::StreamBase::Write calls node::TLSWrap::DoWrite with a freshly
 allocated WriteWrap object as first argument. If the DoWrite method
 does not return an error, this object is passed back to the caller as
 part of a StreamWriteResult structure. This may be exploited to
 corrupt memory leading to a Denial of Service or potentially other
 exploits (bsc#1180553)
 * CVE-2020-8287: HTTP Request Smuggling allow two copies of a header
 field in a http request. For example, two Transfer-Encoding header
 fields. In this case Node.js identifies the first header field and
 ignores the second. This can lead to HTTP Request Smuggling
 ([link moved to references]). (bsc#1180554)
 * CVE-2020-1971: OpenSSL - EDIPARTYNAME NULL pointer de-reference (High)
 This is a vulnerability in OpenSSL which may be exploited through
 Node.js. (bsc#1179491)

New upstream LTS version 12.20.0:
 * deps:
 + update llhttp '2.1.2' -> '2.1.3'
 + update uv '1.39.0' -> '1.40.0'
 + update uvwasi '0.0.10' -> '0.0.11'
 * fs: add .ref() and .unref() methods to watcher classes
 * http: added scheduling option to http agent
 * module:
 + exports pattern support
 + named exports for CJS via static analysis
 * n-api: add more property defaults (gh#35214)");

  script_tag(name:"affected", value:"'nodejs12' package(s) on SUSE Linux Enterprise Module for Web Scripting 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs12", rpm:"nodejs12~12.20.1~1.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-debuginfo", rpm:"nodejs12-debuginfo~12.20.1~1.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-debugsource", rpm:"nodejs12-debugsource~12.20.1~1.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-devel", rpm:"nodejs12-devel~12.20.1~1.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-docs", rpm:"nodejs12-docs~12.20.1~1.26.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm12", rpm:"npm12~12.20.1~1.26.1", rls:"SLES12.0"))) {
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
