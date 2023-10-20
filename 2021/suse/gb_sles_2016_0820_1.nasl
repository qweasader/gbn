# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0820.1");
  script_cve_id("CVE-2016-1950", "CVE-2016-1952", "CVE-2016-1953", "CVE-2016-1954", "CVE-2016-1957", "CVE-2016-1958", "CVE-2016-1960", "CVE-2016-1961", "CVE-2016-1962", "CVE-2016-1964", "CVE-2016-1965", "CVE-2016-1966", "CVE-2016-1974", "CVE-2016-1977", "CVE-2016-1978", "CVE-2016-1979", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:07 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0820-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0820-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160820-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2016:0820-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox was updated to 38.7.0 ESR, fixing the following security issues:
MFSA 2016-16/CVE-2016-1952/CVE-2016-1953:
Miscellaneous memory safety hazards (rv:45.0 / rv:38.7)
MFSA 2016-17/CVE-2016-1954:
Local file overwriting and potential privilege escalation through CSP reports MFSA 2016-20/CVE-2016-1957:
Memory leak in libstagefright when deleting an array during MP4 processing MFSA 2016-21/CVE-2016-1958:
Displayed page address can be overridden MFSA 2016-23/CVE-2016-1960:
Use-after-free in HTML5 string parser MFSA 2016-24/CVE-2016-1961:
Use-after-free in SetBody MFSA 2016-25/CVE-2016-1962:
Use-after-free when using multiple WebRTC data channels MFSA 2016-27/CVE-2016-1964:
Use-after-free during XML transformations MFSA 2016-28/CVE-2016-1965:
Addressbar spoofing though history navigation and Location protocol property MFSA 2016-31/CVE-2016-1966:
Memory corruption with malicious NPAPI plugin MFSA 2016-34/CVE-2016-1974:
Out-of-bounds read in HTML parser following a failed allocation MFSA 2016-35/CVE-2016-1950:
Buffer overflow during ASN.1 decoding in NSS MFSA 2016-37/CVE-2016-1977/CVE-2016-2790/CVE-2016-2791/
CVE-2016-2792/CVE-2016-2793/CVE-2016-2794/CVE-2016-2795/
CVE-2016-2796/CVE-2016-2797/CVE-2016-2798/CVE-2016-2799/
CVE-2016-2800/CVE-2016-2801/CVE-2016-2802:
Font vulnerabilities in the Graphite 2 library.
Mozilla NSPR was updated to version 4.12, fixing following bugs:
Added a PR_GetEnvSecure function, which attempts to detect if the program is being executed with elevated privileges, and returns NULL if detected. It is recommended to use this function in general purpose library code.
Fixed a memory allocation bug related to the PR_*printf functions Exported API PR_DuplicateEnvironment, which had already been added in NSPR 4.10.9 Several minor correctness and compatibility fixes.
Mozilla NSS was updated to fix security issues:
MFSA 2016-15/CVE-2016-1978:
Use-after-free in NSS during SSL connections in low memory MFSA 2016-35/CVE-2016-1950:
Buffer overflow during ASN.1 decoding in NSS MFSA 2016-36/CVE-2016-1979:
Use-after-free during processing of DER encoded keys in NSS.");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~38.7.0esr~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~38.7.0esr~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.12~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.12~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.12~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.20.2~0.7.2", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.20.2~0.7.2", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.20.2~0.7.2", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.20.2~0.7.2", rls:"SLES10.0SP4"))) {
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
