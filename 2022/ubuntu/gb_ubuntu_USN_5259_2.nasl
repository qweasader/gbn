# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845358");
  script_cve_id("CVE-2017-9525", "CVE-2019-9704", "CVE-2019-9705", "CVE-2019-9706");
  script_tag(name:"creation_date", value:"2022-05-07 01:00:27 +0000 (Sat, 07 May 2022)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-16 18:44:00 +0000 (Thu, 16 Dec 2021)");

  script_name("Ubuntu: Security Advisory (USN-5259-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5259-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5259-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cron' package(s) announced via the USN-5259-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5259-1 fixed several vulnerabilities in Cron. This update provides
the corresponding update for Ubuntu 18.04 LTS.

Original advisory details:

 It was discovered that the postinst maintainer script in Cron unsafely
 handled file permissions during package install or update operations.
 An attacker could possibly use this issue to perform a privilege
 escalation attack. (CVE-2017-9525)

 Florian Weimer discovered that Cron incorrectly handled certain memory
 operations during crontab file creation. An attacker could possibly use
 this issue to cause a denial of service. (CVE-2019-9704)

 It was discovered that Cron incorrectly handled user input during crontab
 file creation. An attacker could possibly use this issue to cause a denial
 of service. (CVE-2019-9705)

 It was discovered that Cron contained a use-after-free vulnerability in
 its force_rescan_user function. An attacker could possibly use this issue
 to cause a denial of service. (CVE-2019-9706)");

  script_tag(name:"affected", value:"'cron' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cron", ver:"3.0pl1-128.1ubuntu1.1", rls:"UBUNTU18.04 LTS"))) {
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
