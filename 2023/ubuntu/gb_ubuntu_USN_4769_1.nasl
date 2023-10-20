# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2021.4769.1");
  script_cve_id("CVE-2014-3563", "CVE-2015-6918", "CVE-2015-6941", "CVE-2017-12791", "CVE-2017-14695", "CVE-2017-14696", "CVE-2018-15750", "CVE-2018-15751");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-20 01:17:00 +0000 (Thu, 20 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-4769-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4769-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4769-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt' package(s) announced via the USN-4769-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Salt allowed remote attackers to write to
arbitrary files via a special crafted file. An attacker could use this
vulnerability to cause a DoS or possibly execute arbitrary code. This
issue only affected Ubuntu 14.04 ESM. (CVE-2014-3563)

Andreas Stieger discovered that Salt exposed git usernames and passwords
in log files. An attacker could use this issue to retrieve sensitive
information. This issue only affected Ubuntu 14.04 ESM. (CVE-2015-6918).

It was discovered that Salt exposed password authentication
credentials in log files. An attacker could use this issue to retrieve
sensitive information. This issue only affected Ubuntu 14.04 ESM.
(CVE-2015-6941)

It was discovered that Salt allowed remote attackers to write to
arbitrary files via a special crafted file. An attacker could use this
issue to cause a DoS or possibly execute arbitrary code. (CVE-2017-12791,
CVE-2017-14695, CVE-2017-14696)

It was discovered that Salt allowed remote attackers to determine which
files exist on the server. An attacker could use this issue to extract
sensitive information. This issue only affected Ubuntu 16.04 ESM.
(CVE-2018-15750)

It was discovered that Salt allowed users to bypass authentication. An
attacker could use this issue to extract sensitive information, execute
arbitrary code or crash the server. This issue only affected Ubuntu 16.04
ESM. (CVE-2018-15751)");

  script_tag(name:"affected", value:"'salt' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"salt-common", ver:"0.17.5+ds-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-master", ver:"0.17.5+ds-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-minion", ver:"0.17.5+ds-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-ssh", ver:"0.17.5+ds-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-syndic", ver:"0.17.5+ds-1ubuntu0.1~esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"salt-api", ver:"2015.8.8+ds-1ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-cloud", ver:"2015.8.8+ds-1ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-common", ver:"2015.8.8+ds-1ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-master", ver:"2015.8.8+ds-1ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-minion", ver:"2015.8.8+ds-1ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-proxy", ver:"2015.8.8+ds-1ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-ssh", ver:"2015.8.8+ds-1ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-syndic", ver:"2015.8.8+ds-1ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
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
