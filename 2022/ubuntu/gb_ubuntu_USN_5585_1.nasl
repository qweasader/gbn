# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845500");
  script_cve_id("CVE-2018-19351", "CVE-2018-21030", "CVE-2019-10255", "CVE-2019-10856", "CVE-2019-9644", "CVE-2020-26215", "CVE-2022-24758", "CVE-2022-29238");
  script_tag(name:"creation_date", value:"2022-08-31 01:00:38 +0000 (Wed, 31 Aug 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-08 16:28:25 +0000 (Fri, 08 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-5585-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5585-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5585-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jupyter-notebook' package(s) announced via the USN-5585-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Jupyter Notebook incorrectly handled certain notebooks.
An attacker could possibly use this issue of lack of Content Security Policy
in Nbconvert to perform cross-site scripting (XSS) attacks on the notebook
server. This issue only affected Ubuntu 18.04 LTS. (CVE-2018-19351)

It was discovered that Jupyter Notebook incorrectly handled certain SVG
documents. An attacker could possibly use this issue to perform cross-site
scripting (XSS) attacks. This issue only affected Ubuntu 18.04 LTS.
(CVE-2018-21030)

It was discovered that Jupyter Notebook incorrectly filtered certain URLs on
the login page. An attacker could possibly use this issue to perform
open-redirect attack. This issue only affected Ubuntu 18.04 LTS.
(CVE-2019-10255)

It was discovered that Jupyter Notebook had an incomplete fix for
CVE-2019-10255. An attacker could possibly use this issue to perform
open-redirect attack using empty netloc. (CVE-2019-10856)

It was discovered that Jupyter Notebook incorrectly handled the inclusion of
remote pages on Jupyter server. An attacker could possibly use this issue to
perform cross-site script inclusion (XSSI) attacks. This issue only affected
Ubuntu 18.04 LTS. (CVE-2019-9644)

It was discovered that Jupyter Notebook incorrectly filtered certain URLs to a
notebook. An attacker could possibly use this issue to perform open-redirect
attack. This issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.
(CVE-2020-26215)

It was discovered that Jupyter Notebook server access logs were not protected.
An attacker having access to the notebook server could possibly use this issue
to get access to steal sensitive information such as auth/cookies.
(CVE-2022-24758)

It was discovered that Jupyter Notebook incorrectly configured hidden files on
the server. An authenticated attacker could possibly use this issue to see
unwanted sensitive hidden files from the server which may result in getting
full access to the server. This issue only affected Ubuntu 20.04 LTS and
Ubuntu 22.04 LTS. (CVE-2022-29238)");

  script_tag(name:"affected", value:"'jupyter-notebook' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"jupyter-notebook", ver:"5.2.2-1ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-notebook", ver:"5.2.2-1ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-notebook", ver:"5.2.2-1ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"jupyter-notebook", ver:"6.0.3-2ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-notebook", ver:"6.0.3-2ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"jupyter-notebook", ver:"6.4.8-1ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-notebook", ver:"6.4.8-1ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
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
