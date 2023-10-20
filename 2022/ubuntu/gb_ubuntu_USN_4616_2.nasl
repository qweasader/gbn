# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2020.4616.2");
  script_cve_id("CVE-2018-14036", "CVE-2020-16126");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-06 16:16:00 +0000 (Thu, 06 Sep 2018)");

  script_name("Ubuntu: Security Advisory (USN-4616-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4616-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4616-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'accountsservice' package(s) announced via the USN-4616-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4616-1 fixed several vulnerabilities in AccountsService. This update provides
the corresponding update for Ubuntu 14.04 ESM.

Original advisory details:

 Kevin Backhouse discovered that AccountsService incorrectly dropped
 privileges. A local user could possibly use this issue to cause
 AccountsService to crash or hang, resulting in a denial of service.
 (CVE-2020-16126)

 Matthias Gerstner discovered that AccountsService incorrectly handled
 certain path checks. A local attacker could possibly use this issue to
 read arbitrary files. (CVE-2018-14036)");

  script_tag(name:"affected", value:"'accountsservice' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"accountsservice", ver:"0.6.35-0ubuntu7.3+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaccountsservice0", ver:"0.6.35-0ubuntu7.3+esm2", rls:"UBUNTU14.04 LTS"))) {
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
