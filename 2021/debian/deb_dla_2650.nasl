# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892650");
  script_cve_id("CVE-2020-28007", "CVE-2020-28008", "CVE-2020-28009", "CVE-2020-28011", "CVE-2020-28012", "CVE-2020-28013", "CVE-2020-28014", "CVE-2020-28015", "CVE-2020-28017", "CVE-2020-28019", "CVE-2020-28020", "CVE-2020-28021", "CVE-2020-28022", "CVE-2020-28023", "CVE-2020-28024", "CVE-2020-28025", "CVE-2020-28026");
  script_tag(name:"creation_date", value:"2021-05-06 03:02:13 +0000 (Thu, 06 May 2021)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-10 16:13:00 +0000 (Mon, 10 May 2021)");

  script_name("Debian: Security Advisory (DLA-2650-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2650-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2650-1");
  script_xref(name:"URL", value:"https://www.qualys.com/2021/05/04/21nails/21nails.txt");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/exim4");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'exim4' package(s) announced via the DLA-2650-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Qualys Research Labs reported several vulnerabilities in Exim, a mail transport agent, which could result in local privilege escalation and remote code execution.

Details can be found in the Qualys advisory at [link moved to references]

For Debian 9 stretch, these problems have been fixed in version 4.89-2+deb9u8.

We recommend that you upgrade your exim4 packages.

For the detailed security status of exim4 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'exim4' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"exim4", ver:"4.89-2+deb9u8", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-base", ver:"4.89-2+deb9u8", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-config", ver:"4.89-2+deb9u8", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-heavy", ver:"4.89-2+deb9u8", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-heavy-dbg", ver:"4.89-2+deb9u8", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-light", ver:"4.89-2+deb9u8", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-light-dbg", ver:"4.89-2+deb9u8", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-dbg", ver:"4.89-2+deb9u8", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-dev", ver:"4.89-2+deb9u8", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"eximon4", ver:"4.89-2+deb9u8", rls:"DEB9"))) {
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
