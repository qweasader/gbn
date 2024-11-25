# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1680.1");
  script_cve_id("CVE-2015-4500", "CVE-2015-4501", "CVE-2015-4506", "CVE-2015-4509", "CVE-2015-4511", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7180");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1680-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1680-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151680-1/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, mozilla-nspr' package(s) announced via the SUSE-SU-2015:1680-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox was updated to version 38.3.0 ESR (bsc#947003), fixing bugs and security issues.
* MFSA 2015-96/CVE-2015-4500/CVE-2015-4501 Miscellaneous memory safety
 hazards (rv:41.0 / rv:38.3)
* MFSA 2015-101/CVE-2015-4506 Buffer overflow in libvpx while parsing vp9
 format video
* MFSA 2015-105/CVE-2015-4511 Buffer overflow while decoding WebM video
* MFSA 2015-106/CVE-2015-4509 Use-after-free while manipulating HTML media
 content
* MFSA 2015-110/CVE-2015-4519 Dragging and dropping images exposes final
 URL after redirects
* MFSA 2015-111/CVE-2015-4520 Errors in the handling of CORS preflight
 request headers
* MFSA 2015-112/CVE-2015-4517/CVE-2015-4521/CVE-2015-4522
 CVE-2015-7174/CVE-2015-7175/CVE-2015-7176/CVE-2015-7177 CVE-2015-7180
 Vulnerabilities found through code inspection More details can be found on [link moved to references]
The Mozilla NSPR library was updated to version 4.10.9, fixing various bugs.");

  script_tag(name:"affected", value:"'MozillaFirefox, mozilla-nspr' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~38.3.0esr~48.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~38.3.0esr~48.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~38.3.0esr~48.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~38.3.0esr~48.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.10.9~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.10.9~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo-32bit", rpm:"mozilla-nspr-debuginfo-32bit~4.10.9~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.10.9~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.10.9~6.1", rls:"SLES12.0"))) {
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
