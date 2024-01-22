# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3511");
  script_cve_id("CVE-2019-9836", "CVE-2023-20593");
  script_tag(name:"creation_date", value:"2023-08-01 04:25:26 +0000 (Tue, 01 Aug 2023)");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-01 19:29:00 +0000 (Tue, 01 Aug 2023)");

  script_name("Debian: Security Advisory (DLA-3511-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3511-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3511-1");
  script_xref(name:"URL", value:"https://lock.cmpxchg8b.com/zenbleed.html");
  script_xref(name:"URL", value:"https://github.com/google/security-research/security/advisories/GHSA-v6wh-rxpg-cmm8");
  script_xref(name:"URL", value:"https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7008.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/amd64-microcode");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'amd64-microcode' package(s) announced via the DLA-3511-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy discovered that under specific microarchitectural circumstances, a vector register in Zen 2 CPUs may not be written to 0 correctly. This flaw allows an attacker to leak register contents across concurrent processes, hyper threads and virtualized guests.

For details please refer to [link moved to references] [link moved to references]

The initial microcode release by AMD only provides updates for second generation EPYC CPUs: Various Ryzen CPUs are also affected, but no updates are available yet. Fixes will be provided in a later update once they are released.

For more specific details and target dates please refer to the AMD advisory at [link moved to references]

For Debian 10 buster, this problem has been fixed in version 3.20230719.1+deb10u1. Additionally the update contains a fix for CVE-2019-9836.

We recommend that you upgrade your amd64-microcode packages.

For the detailed security status of amd64-microcode please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'amd64-microcode' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"amd64-microcode", ver:"3.20230719.1~deb10u1", rls:"DEB10"))) {
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
